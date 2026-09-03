// usb_hid_guard.h
#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <vector>
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// ─────────────────────────────────────────────────────────────────────────────
// KeystrokeTimingThresholds / EvaluateKeystrokeTiming
//
// Pure statistics on inter-keystroke intervals -- no Win32 dependency, fully
// unit-testable with canned data (see usb_logic_test.cpp).
//
// Heuristic: programmatic keystroke injection (Rubber Ducky / DuckyScript /
// BadUSB firmware) types at a fixed, near-metronomic rate, typically single
// digit to low tens of milliseconds between keystrokes with almost no jitter.
// A human typist's inter-keystroke intervals are both slower on average and
// far more irregular (much larger standard deviation). Neither threshold
// alone is reliable (a human can burst-type briefly; a script could throttle
// itself) so we require both a low mean AND low jitter before flagging, and
// we always report the underlying evidence rather than a bare boolean so a
// human/analyst can judge borderline cases.
// ─────────────────────────────────────────────────────────────────────────────
namespace KeystrokeTimingThresholds {
    constexpr size_t kMinSamples = 5;          // need at least this many intervals
    constexpr double kSuspiciousMeanMs = 30.0;  // mean interval below this...
    constexpr double kSuspiciousStddevMs = 15.0; // ...and jitter below this => suspected
}

struct KeystrokeTimingResult {
    bool   suspected = false;
    size_t sampleCount = 0;      // number of intervals evaluated
    double meanIntervalMs = 0.0;
    double stddevIntervalMs = 0.0;
    double minIntervalMs = 0.0;
};

// intervalsMs: consecutive inter-keystroke gaps, in milliseconds, in the
// order they were observed. Empty or too-short input yields a not-suspected,
// all-zero result.
KeystrokeTimingResult EvaluateKeystrokeTiming(const std::vector<double>& intervalsMs);

// ─────────────────────────────────────────────────────────────────────────────
// HidInjectionGuard
//
// One instance per newly-arrived HID-keyboard-capable USB device. Registers
// (once, globally, via EnsureRawInputRegistered) for raw keyboard input on a
// message-only window, resolves which raw-input device handle corresponds to
// this specific arrival (by VID/PID match against the OS raw-input device
// list), and records key-down timestamps for a bounded observation window.
//
// Thread-safety: OnRawInput() is called from the window-message thread;
// Evaluate()/IsDone() are called from the dedicated worker thread that owns
// this guard. m_mutex guards the shared timestamp buffer.
// ─────────────────────────────────────────────────────────────────────────────
class HidInjectionGuard {
public:
    static constexpr size_t kMaxSamples = 32;      // bounded -- no unbounded growth
    static constexpr int    kWindowSeconds = 5;    // observation window length

    HidInjectionGuard(std::string vid, std::string pid, std::string instanceId);

    // Attempts to resolve which raw-input HANDLE corresponds to this device
    // by matching VID/PID against GetRawInputDeviceList(). Returns false if
    // no matching raw-input keyboard device could be found (best-effort;
    // caller should still proceed, just without keystroke evidence).
    bool ResolveDeviceHandle();

    // Called from the window thread for every WM_INPUT keyboard key-down.
    // No-op if hDevice does not match this guard's resolved device.
    void OnKeyDown(HANDLE hDevice);

    bool IsDone() const;   // true once window elapsed or sample cap reached
    size_t SampleCount() const;

    KeystrokeTimingResult Evaluate() const;

    const std::string& Vid() const { return m_vid; }
    const std::string& Pid() const { return m_pid; }
    const std::string& InstanceId() const { return m_instanceId; }

private:
    std::string m_vid, m_pid, m_instanceId;
    HANDLE      m_matchedDevice = nullptr;
    std::chrono::steady_clock::time_point m_startTime;

    mutable std::mutex m_mutex;
    std::vector<std::chrono::steady_clock::time_point> m_timestamps; // capped at kMaxSamples
};

// Registers the process-wide raw-input keyboard sink on the given target
// window (RIDEV_INPUTSINK -- delivered even when the window is hidden and
// never focused). Safe to call more than once; only the first call takes
// effect. Returns true on success.
bool EnsureRawInputRegistered(HWND targetWindow);
