// resource_pressure.h
//
// RAM + disk auto-lightening, shared pattern duplicated across all 5 (now 6,
// including this Correlator) endpoints -- no shared library between these
// independent CMake projects, same duplication convention already used for
// collector_health.
//
// Design: never reduces WHAT is monitored -- only HOW MUCH evidence is
// retained (log/archive counts) once the whole system is under memory or
// disk pressure. Every endpoint's own bounded-cache eviction logic stays
// untouched; this only feeds an adaptive factor into each endpoint's
// existing retention-count constant.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

enum class PressureTier { Normal, Lightened, Severe };

// Pure decision function -- given the two raw system metrics, returns the
// tier. No OS calls here, so this is directly unit-testable.
inline PressureTier ClassifyPressure(DWORD memory_load_percent,
    uint64_t free_disk_bytes)
{
    constexpr uint64_t kSevereDiskFloor = 500ULL * 1024 * 1024;         // 500 MB
    constexpr uint64_t kLightenedDiskFloor = 2ULL * 1024 * 1024 * 1024; // 2 GB

    if (memory_load_percent >= 92 || free_disk_bytes < kSevereDiskFloor)
        return PressureTier::Severe;
    if (memory_load_percent >= 85 || free_disk_bytes < kLightenedDiskFloor)
        return PressureTier::Lightened;
    return PressureTier::Normal;
}

inline const char* PressureTierToString(PressureTier tier)
{
    switch (tier) {
    case PressureTier::Lightened: return "lightened";
    case PressureTier::Severe:    return "severe";
    default:                      return "normal";
    }
}

// Multiply a base retention count/cap by this to get the effective,
// pressure-adjusted value (always >= 1 via the caller's own floor clamp).
inline double PressureTierToFactor(PressureTier tier)
{
    switch (tier) {
    case PressureTier::Lightened: return 0.5;
    case PressureTier::Severe:    return 0.25;
    default:                      return 1.0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourcePressureMonitor
//
// Periodically (caller decides the cadence, e.g. every 15-30s from an
// existing ticker/status thread) samples system-wide RAM load
// (GlobalMemoryStatusEx) and free disk space on the volume holding the
// endpoint's log directory (GetDiskFreeSpaceExW), and tracks the current
// tier with hysteresis: only de-escalates after kDeescalateAfterGoodChecks
// consecutive normal-range samples, so a brief dip doesn't flap the tier.
// ─────────────────────────────────────────────────────────────────────────────
class ResourcePressureMonitor {
public:
    ResourcePressureMonitor() = default;
    explicit ResourcePressureMonitor(std::wstring path_on_volume)
        : path_(std::move(path_on_volume)) {
    }

    // Allows setting/replacing the monitored path after construction, for
    // endpoints where the log directory isn't known until Start() runs.
    void SetPath(std::wstring path_on_volume) { path_ = std::move(path_on_volume); }

    void Update()
    {
        MEMORYSTATUSEX mem{};
        mem.dwLength = sizeof(mem);
        DWORD load = 0;
        if (GlobalMemoryStatusEx(&mem)) load = mem.dwMemoryLoad;

        ULARGE_INTEGER free_bytes{};
        uint64_t free_disk = UINT64_MAX;   // query failure must never falsely trigger "severe"
        if (!path_.empty() &&
            GetDiskFreeSpaceExW(path_.c_str(), &free_bytes, nullptr, nullptr))
            free_disk = free_bytes.QuadPart;

        const PressureTier observed = ClassifyPressure(load, free_disk);
        if (observed != PressureTier::Normal) {
            tier_.store(observed, std::memory_order_relaxed);
            good_checks_ = 0;
        }
        else if (tier_.load(std::memory_order_relaxed) != PressureTier::Normal) {
            if (++good_checks_ >= kDeescalateAfterGoodChecks)
                tier_.store(PressureTier::Normal, std::memory_order_relaxed);
        }
    }

    PressureTier GetTier()   const { return tier_.load(std::memory_order_relaxed); }
    double       GetFactor() const { return PressureTierToFactor(GetTier()); }

private:
    static constexpr int kDeescalateAfterGoodChecks = 3;

    std::wstring               path_;
    std::atomic<PressureTier> tier_{ PressureTier::Normal };
    int                        good_checks_ = 0;
};

// Applies factor to a base cap, clamped to a floor so retention never hits 0.
inline size_t AdaptiveCap(size_t base_cap, size_t floor_cap, double factor)
{
    const size_t scaled = static_cast<size_t>(static_cast<double>(base_cap) * factor);
    return scaled > floor_cap ? scaled : floor_cap;
}
