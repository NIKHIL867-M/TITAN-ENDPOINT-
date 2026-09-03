
#include "file_tracker.h"
#include "file_logger.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <cwchar>

namespace titan::fim
{

    TempTracker::TempTracker(FileLogger* logger,
        uint32_t minimum_lifetime_seconds,
        FileProcessor* processor)
        : logger_(logger)
        , processor_(processor)
        , minimum_lifetime_seconds_(minimum_lifetime_seconds)
    {
    }

    // =========================================================================
    // TrackEvent
    // Called for every Bucket B event. Returns true if the event was elevated.
    // =========================================================================

    bool TempTracker::TrackEvent(const FileEvent& event)
    {
        if (!logger_) return false;
        if (event.path.empty() || event.path == L"unresolved") return false;

        std::wstring dir = ExtractDir(event.path);

        // FIX (Bug B): derive effective_pid the same way the bucket key does.
        uint32_t effective_pid = event.creator_pid > 0
            ? event.creator_pid
            : event.pid;

        std::wstring key = BucketKey(dir, effective_pid);

        std::lock_guard<std::mutex> lock(mutex_);

        if (effective_pid > 4)
            RememberTempFile(event, effective_pid);

        // Get or create bucket
        auto& bucket = buckets_[key];
        if (bucket.directory.empty())
        {
            bucket.directory = dir;
            bucket.creator_pid = effective_pid;
            bucket.creator_name = event.process_name;
            bucket.first_seen = std::chrono::steady_clock::now();
        }
        bucket.last_seen = std::chrono::steady_clock::now();

        if (buckets_.size() > TEMP_TRACKER_MAX_ENTRIES)
            EvictCleanBuckets();

        // =====================================================================
        // FIX (RAM Bomb): Check detail limit before inserting into files map.
        //
        // If the bucket already has a detailed entry for this path, update it
        // normally regardless of the limit (the entry already exists, no new
        // allocation).
        //
        // If this is a NEW path AND the files map is already at the limit,
        // just increment mass_file_count and total_created, then return.
        // No anomaly check is run on aggregated files — they have no path data.
        // =====================================================================
        std::wstring path_lower = ToLower(event.path);
        auto fit = bucket.files.find(path_lower);
        bool is_new = (fit == bucket.files.end());

        if (is_new && bucket.files.size() >= TEMP_BUCKET_DETAIL_LIMIT)
        {
            bucket.mass_event_count++;
            if (event.action == FileAction::CREATE)
            {
                bucket.mass_file_count++;
                bucket.total_created++;
            }
            else if (event.action == FileAction::DELETE_F)
            {
                bucket.total_deleted++;
            }
            return false;
        }

        // --- Detailed tracking path ---
        auto& entry = bucket.files[path_lower];
        is_new = entry.path.empty(); // re-check after potential insert

        if (is_new)
        {
            entry.path = event.path;
            entry.file_key = event.file_key;
            entry.creator_pid = effective_pid;
            entry.creator_name = event.process_name;
            entry.born_at = std::chrono::steady_clock::now();
            entry.state = TempFileState::WATCHING;
            bucket.total_created++;
            bucket.total_alive++;

        }
        entry.last_seen = std::chrono::steady_clock::now();

        // Handle DELETE — file is gone
        if (event.action == FileAction::DELETE_F)
        {
            const bool was_elevated = entry.state == TempFileState::ELEVATED;
            const auto lifetime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - entry.born_at).count();
            auto& churn = dir_churn_[ToLower(bucket.directory)];
            if (churn.lifetime_samples == 0)
                churn.lifetime_avg_seconds = static_cast<double>(lifetime);
            else
                churn.lifetime_avg_seconds =
                    (churn.lifetime_avg_seconds * 0.9) +
                    (static_cast<double>(lifetime) * 0.1);
            ++churn.lifetime_samples;
            entry.state = TempFileState::DROPPED;
            bucket.total_alive = (bucket.total_alive > 0)
                ? bucket.total_alive - 1 : 0;
            bucket.total_deleted++;

            if (!was_elevated
                && !entry.cross_pid && !entry.was_renamed)
            {
                return false;
            }
        }

        // Handle WRITE
        if (event.action == FileAction::WRITE)
            entry.write_count++;

        // Cross-process access check
        if (event.pid != bucket.creator_pid && event.action != FileAction::DELETE_F)
        {
            entry.cross_pid = true;
            bool already = false;
            for (const auto& op : entry.other_pids)
                if (op.first == event.pid) { already = true; break; }
            if (!already && entry.other_pids.size() < TEMP_OTHER_PID_LIMIT)
                entry.other_pids.emplace_back(event.pid, event.process_name);
        }

        // Handle RENAME — check if renamed to executable
        if (event.action == FileAction::RENAME)
        {
            entry.was_renamed = true;
            if (IsExecutableExtension(event.path))
            {
                ElevateToBucketA(bucket, entry, "rename_to_executable");
                return true;
            }
        }

        return CheckAnomalies(bucket, entry, event);
    }

    std::wstring TempTracker::TempIdentity(const FileEvent& event) const
    {
        // The Kernel-File provider's FileKey can legitimately differ between
        // task families for one pathname. Keep the lifecycle path-stable and
        // retain the latest non-zero kernel key as corroborating evidence.
        return L"path:" + ToLower(event.path);
    }

    void TempTracker::RemoveRecentTemp(const std::wstring& identity)
    {
        const auto found = recent_temp_files_.find(identity);
        if (found == recent_temp_files_.end()) return;
        const uint32_t pid = found->second.creator_pid;
        recent_temp_files_.erase(found);
        auto pit = recent_temp_ids_by_pid_.find(pid);
        if (pit == recent_temp_ids_by_pid_.end()) return;
        auto& ids = pit->second;
        ids.erase(std::remove(ids.begin(), ids.end(), identity), ids.end());
        if (ids.empty()) recent_temp_ids_by_pid_.erase(pit);
    }

    void TempTracker::RememberTempFile(const FileEvent& event,
        uint32_t effective_pid)
    {
        const auto now = std::chrono::steady_clock::now();
        std::wstring identity = TempIdentity(event);

        // Some ETW operations omit FileKey. Reuse a path-tracked identity when
        // it represents this same live path.
        if (event.file_key == 0)
        {
            const std::wstring wanted = ToLower(event.path);
            auto pit = recent_temp_ids_by_pid_.find(effective_pid);
            if (pit != recent_temp_ids_by_pid_.end())
            {
                for (const auto& candidate : pit->second)
                {
                    const auto fit = recent_temp_files_.find(candidate);
                    if (fit != recent_temp_files_.end() &&
                        ToLower(fit->second.path) == wanted)
                    {
                        identity = candidate;
                        break;
                    }
                }
            }
        }

        auto [it, inserted] = recent_temp_files_.try_emplace(identity);
        auto& recent = it->second;
        if (inserted || event.action == FileAction::CREATE)
        {
            recent = RecentTempActivity{};
            recent.identity = identity;
            recent.path = event.path;
            recent.file_key = event.file_key;
            recent.creator_pid = effective_pid;
            recent.creator_tid = event.tid;
            recent.born_at = now;
            recent.active = true;
        }
        recent.last_seen = now;
        recent.last_tid = event.tid;
        if (event.file_key != 0)
            recent.file_key = event.file_key;
        if (recent.process_name.empty() || recent.process_name == L"unknown")
        {
            recent.process_name = event.process_name;
            if ((recent.process_name.empty() ||
                recent.process_name == L"unknown") && processor_)
                recent.process_name = processor_->ProcessNameForPid(effective_pid);
        }

        switch (event.action)
        {
        case FileAction::CREATE: ++recent.create_count; break;
        case FileAction::WRITE: ++recent.write_count; break;
        case FileAction::RENAME: ++recent.rename_count; recent.path = event.path; break;
        case FileAction::DELETE_F: ++recent.delete_count; recent.active = false; break;
        default: break;
        }

        auto& ids = recent_temp_ids_by_pid_[effective_pid];
        ids.erase(std::remove(ids.begin(), ids.end(), identity), ids.end());
        ids.push_back(identity);
        while (ids.size() > RECENT_TEMP_FILES_PER_PID)
            ids.pop_front();

        while (recent_temp_files_.size() > RECENT_TEMP_FILE_LIMIT)
        {
            auto oldest = std::min_element(recent_temp_files_.begin(),
                recent_temp_files_.end(),
                [](const auto& a, const auto& b) {
                    return a.second.last_seen < b.second.last_seen;
                });
            if (oldest == recent_temp_files_.end()) break;
            RemoveRecentTemp(oldest->first);
        }
    }

    // =========================================================================
    // CheckAnomalies
    // =========================================================================

    bool TempTracker::CheckAnomalies(TempBucket& bucket,
        TempFileEntry& entry,
        const FileEvent& event)
    {
        if (entry.state == TempFileState::ELEVATED) return true;

        auto now = std::chrono::steady_clock::now();
        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.born_at).count();

        // R1: Cross-process access by a suspicious process
        if (entry.cross_pid && !entry.other_pids.empty())
        {
            for (const auto& op : entry.other_pids)
            {
                std::wstring name = ToLower(op.second);
                if (name.find(L"powershell") != std::wstring::npos ||
                    name.find(L"cmd.exe") != std::wstring::npos ||
                    name.find(L"wscript") != std::wstring::npos ||
                    name.find(L"cscript") != std::wstring::npos ||
                    name.find(L"mshta") != std::wstring::npos ||
                    name.find(L"rundll32") != std::wstring::npos ||
                    name.find(L"regsvr32") != std::wstring::npos ||
                    name.find(L"certutil") != std::wstring::npos ||
                    name.find(L"bitsadmin") != std::wstring::npos)
                {
                    ElevateToBucketA(bucket, entry, "suspicious_process_cross_access");
                    return true;
                }
            }
        }

        // R3: Long-lived temp file still being accessed
        if (age_s >= static_cast<long long>(
            LifetimeThresholdSeconds(bucket.directory)))
        {
            ElevateToBucketA(bucket, entry, "long_lived_temp_file");
            return true;
        }

        // R5: Document file inside a high-churn zone
        {
            std::wstring dir_lower = ToLower(bucket.directory);
            auto dit = dir_churn_.find(dir_lower);
            if (dit != dir_churn_.end() && dit->second.is_high_churn)
            {
                if (IsDocumentExtension(event.path))
                {
                    ElevateToBucketA(bucket, entry, "document_in_high_churn_zone");
                    return true;
                }
            }
        }

        return false;
    }

    // =========================================================================
    // ElevateToBucketA
    // =========================================================================

    void TempTracker::ElevateToBucketA(TempBucket& bucket,
        TempFileEntry& entry,
        const std::string& reason)
    {
        entry.state = TempFileState::ELEVATED;
        bucket.has_anomaly = true;

        if (logger_)
        {
            std::string json = BuildElevatedJson(bucket, entry, reason);
            logger_->Log(json, LogSeverity::ALERT);
        }
    }

    // =========================================================================
    // Maintenance — called every 30 s from the monitor loop
    // =========================================================================

    void TempTracker::Maintenance()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::steady_clock::now();

        for (auto bit = buckets_.begin(); bit != buckets_.end(); )
        {
            TempBucket& bucket = bit->second;

            for (auto& [path, entry] : bucket.files)
            {
                if (entry.state == TempFileState::WATCHING ||
                    entry.state == TempFileState::TRUSTED_AGING)
                {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        now - entry.born_at).count();
                    if (age >= static_cast<long long>(
                        LifetimeThresholdSeconds(bucket.directory)))
                        ElevateToBucketA(bucket, entry, "maintenance_long_lived_temp");
                }
            }

            auto idle_s = std::chrono::duration_cast<std::chrono::seconds>(
                now - bucket.last_seen).count();
            bool all_resolved = (bucket.total_alive == 0);
            bool long_idle = (idle_s > 10);

            if (all_resolved || long_idle)
            {
                if (bucket.total_created > 0 && bucket.has_anomaly)
                    CompressAndLogBucket(bucket);
                bit = buckets_.erase(bit);
                continue;
            }

            ++bit;
        }

        // Reset per-second churn counters every 5 seconds
        for (auto& [dir, churn] : dir_churn_)
        {
            auto window_age = std::chrono::duration_cast<std::chrono::seconds>(
                now - churn.window_start).count();
            if (window_age >= 5)
            {
                churn.count_this_second = 0;
                churn.window_start = now;
                churn.is_high_churn = false;
            }
        }

        for (auto it = dir_churn_.begin(); it != dir_churn_.end(); )
        {
            const auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_seen).count();
            if (idle > static_cast<long long>(DIR_CHURN_IDLE_SECONDS))
                it = dir_churn_.erase(it);
            else
                ++it;
        }

        for (auto it = recent_temp_files_.begin();
            it != recent_temp_files_.end(); )
        {
            if (now - it->second.last_seen >
                std::chrono::seconds(TEMP_RELATION_WINDOW_SECONDS))
            {
                const std::wstring identity = it->first;
                ++it;
                RemoveRecentTemp(identity);
            }
            else
                ++it;
        }
    }

    // =========================================================================
    // CompressAndLogBucket
    // =========================================================================

    void TempTracker::CompressAndLogBucket(TempBucket& bucket)
    {
        if (!logger_) return;

        uint32_t elevated_count = 0;
        for (const auto& [p, e] : bucket.files)
            if (e.state == TempFileState::ELEVATED) elevated_count++;

        std::string json = BuildSummaryJson(bucket, elevated_count);
        logger_->Log(json, LogSeverity::INFO);
    }

    // =========================================================================
    // UpdateChurn — called ONLY from RecordDirectoryEvent (Bug A fix)
    // =========================================================================

    void TempTracker::UpdateChurn(const std::wstring& dir)
    {
        std::wstring key = ToLower(dir);
        auto& entry = dir_churn_[key];
        auto  now = std::chrono::steady_clock::now();
        entry.last_seen = now;

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.window_start).count();

        if (elapsed >= 1)
        {
            entry.count_this_second = 0;
            entry.window_start = now;
        }

        entry.count_this_second++;

        if (entry.count_this_second >= HIGH_CHURN_THRESHOLD)
            entry.is_high_churn = true;

        if (dir_churn_.size() > DIR_CHURN_MAX_ENTRIES)
        {
            auto oldest = dir_churn_.begin();
            for (auto it = dir_churn_.begin(); it != dir_churn_.end(); ++it)
                if (it->second.last_seen < oldest->second.last_seen)
                    oldest = it;
            dir_churn_.erase(oldest);
        }
    }

    // =========================================================================
    // RecordDirectoryEvent — sole entry point for churn counting (Bug A fix)
    // =========================================================================

    void TempTracker::RecordDirectoryEvent(const std::wstring& path)
    {
        if (path.empty() || path == L"unresolved") return;
        std::wstring dir = ExtractDir(path);
        std::lock_guard<std::mutex> lock(mutex_);
        UpdateChurn(dir);
    }

    // =========================================================================
    // IsHighChurnDirectory
    // =========================================================================

    bool TempTracker::IsHighChurnDirectory(const std::wstring& dir) const
    {
        std::wstring key = ToLower(dir);
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = dir_churn_.find(key);
        if (it == dir_churn_.end()) return false;
        return it->second.is_high_churn;
    }

    void TempTracker::ObserveRelatedEvent(const FileEvent& event)
    {
        if (!logger_ || event.pid <= 4 || event.path.empty() ||
            event.path == L"unresolved" || IsKnownTempPath(event.path))
            return;

        const auto now = std::chrono::steady_clock::now();
        std::vector<RecentTempActivity> origins;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto pit = recent_temp_ids_by_pid_.find(event.pid);
            if (pit == recent_temp_ids_by_pid_.end()) return;
            for (auto id = pit->second.rbegin(); id != pit->second.rend(); ++id)
            {
                const auto fit = recent_temp_files_.find(*id);
                if (fit == recent_temp_files_.end()) continue;
                if (now - fit->second.last_seen >
                    std::chrono::seconds(TEMP_RELATION_WINDOW_SECONDS))
                    continue;
                if (ToLower(fit->second.path) == ToLower(event.path) ||
                    (event.file_key != 0 &&
                        event.file_key == fit->second.file_key))
                    continue;
                origins.push_back(fit->second);
            }
        }
        if (origins.empty()) return;

        const std::wstring extension = GetExtension(event.path);
        std::string reason = "same_process_related_file_activity";
        LogSeverity severity = LogSeverity::INFO;
        if (extension == L".dll" || extension == L".sys" ||
            IsExecutableExtension(event.path))
        {
            reason = "temp_process_touched_executable_target";
            severity = LogSeverity::WARNING;
        }
        else if (IsProtectedPath(event.path) || IsStartupPath(event.path))
        {
            reason = "temp_process_touched_protected_target";
            severity = LogSeverity::WARNING;
        }

        const char* action = "unknown";
        switch (event.action)
        {
        case FileAction::CREATE: action = "create"; break;
        case FileAction::WRITE: action = "write"; break;
        case FileAction::DELETE_F: action = "delete"; break;
        case FileAction::RENAME: action = "rename"; break;
        case FileAction::SET_INFO: action = "set_info"; break;
        default: return;
        }

        for (const auto& origin : origins)
        {
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - origin.born_at).count();
            const bool same_thread = event.tid != 0 &&
                (event.tid == origin.last_tid ||
                    event.tid == origin.creator_tid);
            std::ostringstream json;
            json << "{\"endpoint\":\"file_integrity\","
                << "\"type\":\"temp_related_activity\","
                << "\"t_unix_ms\":"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                    event.timestamp.time_since_epoch()).count() << ","
                << "\"reason\":\"" << reason << "\","
                << "\"correlation_basis\":\""
                << (same_thread ? "same_actor_thread" : "same_actor_pid")
                << "\","
                << "\"temp_identity\":\"" << WstrToUtf8(origin.identity) << "\","
                << "\"temp_file_key\":" << origin.file_key << ","
                << "\"target_file_key\":" << event.file_key << ","
                << "\"temp_path\":\"" << WstrToUtf8(origin.path) << "\","
                << "\"target_path\":\"" << WstrToUtf8(event.path) << "\","
                << "\"target_action\":\"" << action << "\","
                << "\"pid\":" << event.pid << ","
                << "\"tid\":" << event.tid << ","
                << "\"process\":\"" << WstrToUtf8(
                    event.process_name.empty() ? origin.process_name :
                    event.process_name) << "\","
                << "\"temp_age_seconds\":" << age << ","
                << "\"temp_active\":" << (origin.active ? "true" : "false") << ","
                << "\"temp_create_count\":" << origin.create_count << ","
                << "\"temp_write_count\":" << origin.write_count << ","
                << "\"temp_rename_count\":" << origin.rename_count << ","
                << "\"temp_delete_count\":" << origin.delete_count
                << "}";
            const std::string key = "temp_related|" +
                WstrToUtf8(origin.identity) + "|" +
                WstrToUtf8(ToLower(event.path)) + "|" + action;
            logger_->LogAggregated(key, json.str(), severity);
        }
    }

    void TempTracker::ObservePathTransition(const FileEvent& event)
    {
        if (!logger_ || event.action != FileAction::RENAME ||
            event.path.empty())
            return;

        RecentTempActivity origin;
        bool found_origin = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto pit = recent_temp_ids_by_pid_.find(event.pid);
            if (pit != recent_temp_ids_by_pid_.end())
            {
                for (auto id = pit->second.rbegin();
                    id != pit->second.rend(); ++id)
                {
                    const auto fit = recent_temp_files_.find(*id);
                    if (fit == recent_temp_files_.end()) continue;
                    const bool path_match = !event.old_path.empty() &&
                        ToLower(fit->second.path) == ToLower(event.old_path);
                    const bool key_match = event.file_key != 0 &&
                        event.file_key == fit->second.file_key;
                    if (!path_match && !key_match) continue;

                    origin = fit->second;
                    found_origin = true;
                    fit->second.path = event.path;
                    fit->second.last_seen = std::chrono::steady_clock::now();
                    fit->second.last_tid = event.tid;
                    ++fit->second.rename_count;
                    break;
                }
            }
        }

        const std::wstring source_path = !event.old_path.empty()
            ? event.old_path
            : (found_origin ? origin.path : L"");
        if (source_path.empty() || !IsKnownTempPath(source_path))
            return;

        const bool left_temp = !IsKnownTempPath(event.path);
        const std::wstring old_ext = GetExtension(source_path);
        const std::wstring new_ext = GetExtension(event.path);
        const bool extension_changed = old_ext != new_ext;
        if (!left_temp && !extension_changed) return;

        std::string reason = left_temp
            ? "temp_moved_to_non_temp_path" : "temp_extension_changed";
        LogSeverity severity = IsExecutableExtension(event.path)
            ? LogSeverity::WARNING : LogSeverity::INFO;
        if (IsExecutableExtension(event.path))
            reason = "temp_renamed_to_executable";

        std::wstring process_name = event.process_name;
        if ((process_name.empty() || process_name == L"unknown") && processor_)
            process_name = processor_->ProcessNameForPid(event.pid);

        std::ostringstream json;
        json << "{\"endpoint\":\"file_integrity\","
            << "\"type\":\"temp_path_transition\","
            << "\"reason\":\"" << reason << "\","
            << "\"old_path\":\"" << WstrToUtf8(source_path) << "\","
            << "\"new_path\":\"" << WstrToUtf8(event.path) << "\","
            << "\"old_extension\":\"" << WstrToUtf8(old_ext) << "\","
            << "\"new_extension\":\"" << WstrToUtf8(new_ext) << "\","
            << "\"file_identity\":\""
            << WstrToUtf8(found_origin ? origin.identity :
                TempIdentity(event)) << "\","
            << "\"file_key\":" << event.file_key << ","
            << "\"pid\":" << event.pid << ","
            << "\"tid\":" << event.tid << ","
            << "\"write_count_before_transition\":"
            << (found_origin ? origin.write_count : 0) << ","
            << "\"process\":\"" << WstrToUtf8(process_name) << "\"}";
        const std::string key = "temp_transition|" +
            WstrToUtf8(ToLower(source_path)) + "|" +
            WstrToUtf8(ToLower(event.path));
        logger_->LogAggregated(key, json.str(), severity);

    }

    // =========================================================================
    // EvictCleanBuckets
    // =========================================================================

    void TempTracker::EvictCleanBuckets()
    {
        std::vector<std::pair<std::chrono::steady_clock::time_point,
            std::wstring>> candidates;

        for (const auto& [k, b] : buckets_)
            candidates.emplace_back(b.last_seen, k);

        std::sort(candidates.begin(), candidates.end());

        const size_t over_limit = buckets_.size() > TEMP_TRACKER_MAX_ENTRIES
            ? buckets_.size() - TEMP_TRACKER_MAX_ENTRIES : 0;
        size_t evict_count = std::max(size_t(1), over_limit);
        evict_count = std::min(evict_count, size_t(128));

        for (size_t i = 0; i < evict_count; ++i)
        {
            auto it = buckets_.find(candidates[i].second);
            if (it != buckets_.end())
            {
                if (it->second.total_created > 0 && it->second.has_anomaly)
                    CompressAndLogBucket(it->second);
                buckets_.erase(it);
            }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    std::wstring TempTracker::BucketKey(const std::wstring& dir, uint32_t pid) const
    {
        return ToLower(dir) + L"|" + std::to_wstring(pid);
    }

    std::wstring TempTracker::ExtractDir(const std::wstring& path) const
    {
        std::filesystem::path p(path);
        return p.has_parent_path() ? p.parent_path().wstring() : path;
    }

    uint32_t TempTracker::LifetimeThresholdSeconds(
        const std::wstring& dir) const
    {
        const auto it = dir_churn_.find(ToLower(dir));
        if (it == dir_churn_.end() || it->second.lifetime_samples < 5)
            return minimum_lifetime_seconds_;
        const double adaptive = it->second.lifetime_avg_seconds * 3.0;
        return static_cast<uint32_t>(std::clamp(adaptive,
            static_cast<double>(minimum_lifetime_seconds_),
            static_cast<double>(TEMP_DEEP_WATCH_SECONDS)));
    }

    // =========================================================================
    // JSON builders
    // =========================================================================

    std::string TempTracker::WstrToUtf8(const std::wstring& ws)
    {
        std::string out;
        out.reserve(ws.size() * 2);
        for (size_t i = 0; i < ws.size(); ++i)
        {
            uint32_t cp = static_cast<uint16_t>(ws[i]);
            if (cp >= 0xD800 && cp <= 0xDBFF)
            {
                if (i + 1 < ws.size())
                {
                    uint32_t low = static_cast<uint16_t>(ws[i + 1]);
                    if (low >= 0xDC00 && low <= 0xDFFF)
                    {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        ++i;
                    }
                    else cp = 0xFFFD;
                }
                else cp = 0xFFFD;
            }
            else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;

            if (cp < 0x80)
            {
                char c = static_cast<char>(cp);
                if (c == '"')  out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "\\t";
                else if (cp < 0x20)
                {
                    char escaped[7] = {};
                    sprintf_s(escaped, "\\u%04X", static_cast<unsigned>(cp));
                    out += escaped;
                }
                else                out += c;
            }
            else if (cp < 0x800)
            {
                out += static_cast<char>(0xC0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else if (cp < 0x10000)
            {
                out += static_cast<char>(0xE0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else
            {
                out += static_cast<char>(0xF0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return out;
    }

    // =========================================================================
    // BuildSummaryJson
    //
    // FIX (RAM Bomb): Now reports both the number of detailed-tracked files
    // and the count of files that exceeded TEMP_BUCKET_DETAIL_LIMIT and were
    // aggregated (no individual path data stored for those).
    //
    // Example output fragment:
    //   "detailed_tracked":50,"mass_aggregated":199950
    // =========================================================================

    std::string TempTracker::BuildSummaryJson(const TempBucket& bucket,
        uint32_t elevated_count) const
    {
        auto now_t = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(
            bucket.last_seen - bucket.first_seen).count();

        std::ostringstream j;
        j << "{";
        j << "\"endpoint\":\"file_integrity\",";
        j << "\"type\":\"temp_batch_summary\",";
        j << "\"directory\":\"" << WstrToUtf8(bucket.directory) << "\",";
        j << "\"creator_pid\":" << bucket.creator_pid << ",";
        j << "\"creator\":\"" << WstrToUtf8(bucket.creator_name) << "\",";
        j << "\"total_created\":" << bucket.total_created << ",";
        j << "\"total_deleted\":" << bucket.total_deleted << ",";
        j << "\"elevated_count\":" << elevated_count << ",";
        j << "\"detailed_tracked\":" << static_cast<uint32_t>(bucket.files.size()) << ",";
        j << "\"mass_aggregated\":" << bucket.mass_file_count << ",";
        j << "\"mass_events\":" << bucket.mass_event_count << ",";
        j << "\"duration_seconds\":" << duration_s << ",";
        j << "\"timestamp\":\"" << ts.str() << "\"";
        j << "}";
        return j.str();
    }

    std::string TempTracker::BuildElevatedJson(const TempBucket& bucket,
        const TempFileEntry& entry,
        const std::string& reason) const
    {
        auto now_t = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            entry.last_seen - entry.born_at).count();

        std::ostringstream j;
        j << "{";
        j << "\"endpoint\":\"file_integrity\",";
        j << "\"type\":\"temp_lifecycle\",";
        j << "\"reason\":\"" << reason << "\",";
        j << "\"path\":\"" << WstrToUtf8(entry.path) << "\",";
        j << "\"directory\":\"" << WstrToUtf8(bucket.directory) << "\",";
        j << "\"creator_pid\":" << entry.creator_pid << ",";
        j << "\"creator\":\"" << WstrToUtf8(entry.creator_name) << "\",";
        j << "\"write_count\":" << entry.write_count << ",";
        j << "\"age_seconds\":" << age_s << ",";
        j << "\"lifetime_threshold_seconds\":"
            << LifetimeThresholdSeconds(bucket.directory) << ",";
        j << "\"was_renamed\":" << (entry.was_renamed ? "true" : "false") << ",";
        j << "\"cross_pid\":" << (entry.cross_pid ? "true" : "false");
        if (processor_ && reason.find("long_lived") != std::string::npos)
        {
            const std::string hash = processor_->HashFileNow(entry.path);
            if (!hash.empty())
                j << ",\"sha256\":\"" << hash << "\"";
        }

        if (!entry.other_pids.empty())
        {
            j << ",\"other_pids\":[";
            for (size_t i = 0; i < entry.other_pids.size(); ++i)
            {
                if (i > 0) j << ",";
                j << "{\"pid\":" << entry.other_pids[i].first
                    << ",\"name\":\"" << WstrToUtf8(entry.other_pids[i].second)
                    << "\"}";
            }
            j << "]";
        }

        j << ",\"timestamp\":\"" << ts.str() << "\"";
        j << "}";
        return j.str();
    }

} // namespace titan::fim
