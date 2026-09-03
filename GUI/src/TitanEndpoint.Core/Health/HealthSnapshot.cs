using TitanEndpoint.Core.Json;

namespace TitanEndpoint.Core.Health;

public enum HealthStatus { Unknown, Healthy, Degraded, Failed }

/// <summary>FORU.TXT section 5: "Distinguish unavailable, starting, healthy, degraded, stopping,
/// stopped, crashed, stale, and incompatible-schema states in the GUI." A richer classification
/// than HealthStatus above (which is just the raw "status" field a producer reports) -- this
/// combines process running-state, health freshness, and schema compatibility, the same inputs
/// EndpointHeaderViewModel's StatusBadgeText already computes, formalized into one named enum so
/// other views (System Health, Overview) can use the identical vocabulary instead of re-deriving
/// their own text.</summary>
public enum EndpointLifecycleState
{
    /// <summary>No manifest entry / never configured / never observed running or logging.</summary>
    Unavailable,
    /// <summary>Process detected running, but no health record has arrived yet.</summary>
    Starting,
    Healthy,
    Degraded,
    /// <summary>A stop was requested and is in flight.</summary>
    Stopping,
    /// <summary>Not running, and the last stop was a clean/requested one (or it was never started).</summary>
    Stopped,
    /// <summary>Was running, is no longer running, and no stop was requested -- an unexpected exit.</summary>
    Crashed,
    /// <summary>Process is running but its most recent health record is older than the
    /// staleness threshold -- a heartbeat that stopped, not necessarily a crash.</summary>
    Stale,
    /// <summary>The producer's health schema_version is higher than this GUI build understands.</summary>
    IncompatibleSchema
}

/// <summary>Normalized view over one collector_health record — every field is honest about being absent.</summary>
public sealed class HealthSnapshot
{
    public required HealthStatus Status { get; init; }
    public required DateTimeOffset ObservedAtUtc { get; init; }
    public bool Final { get; init; }
    public bool EvidenceGap { get; init; }
    public string? ResourcePressure { get; init; }
    public IReadOnlyDictionary<string, long> Counters { get; init; } = new Dictionary<string, long>();

    /// <summary>FORU.TXT section 6: the normalized, versioned collector_health schema fields.
    /// SchemaVersion is null for any endpoint not yet migrated to it (older shape) — callers
    /// must not assume these are always present. SessionId is the field 6.6 needs: "Associate
    /// health with the exact process session. Ignore health from a previous process or
    /// historical file when determining current runtime state" — a health record's SessionId
    /// changing while the GUI believes it's still tracking the same OS process instance is
    /// exactly that "previous process" case (e.g. a PID got reused across an unnoticed restart).</summary>
    public int? SchemaVersion { get; init; }
    public string? ComponentId { get; init; }
    public string? SessionId { get; init; }
    public long? Pid { get; init; }
    public string? ExecutableVersion { get; init; }
    public string? LastError { get; init; }

    /// <summary>The highest health schema_version this GUI build understands. A producer
    /// reporting higher must be treated as EndpointLifecycleState.IncompatibleSchema rather than
    /// silently parsed as if every field it might add were already known.</summary>
    public const int MaxKnownSchemaVersion = 2;

    // FORU.TXT section 5 v2 fields -- additive; a producer not yet emitting one of these leaves
    // it null, which callers must treat as "not reported", never as zero/false.
    public string? EndpointId { get; init; }
    public string? ExecutableHash { get; init; }
    public long? StartedAtUnixMs { get; init; }
    public long? UpdatedAtUnixMs { get; init; }
    public bool? Collecting { get; init; }
    public bool? PersistenceEnabled { get; init; }
    public long? QueueDepth { get; init; }
    public long? QueueCapacity { get; init; }
    public long? QueuePeak { get; init; }
    public long? RecordsSeen { get; init; }
    public long? RecordsWritten { get; init; }
    public long? RecordsDropped { get; init; }
    public long? ParseFailures { get; init; }
    public long? SourceLoss { get; init; }
    public long? WriterFailures { get; init; }
    public long? Rotations { get; init; }
    public long? RetainedBytes { get; init; }
    public long? RetainedFiles { get; init; }
    public string? ShutdownState { get; init; }
    public bool? ShutdownAck { get; init; }

    private static readonly string[] KnownCounterKeys =
    {
        "events_processed", "events_forwarded", "events_compressed", "submitted_events",
        "queue_dropped", "etw_events_lost", "etw_realtime_buffers_lost", "realtime_buffers_lost",
        "processing_errors", "temp_events_coalesced", "watcher_buffer_overflow_count",
        "active_sessions", "restart_count", "join_backlog", "ring_evictions", "flow_evictions",
        "queue_depth", "queue_capacity", "write_failures", "rotation_count",
        "logged", "deduplicated", "logger_failures", "subscription_errors",
        "etw_buffers_lost", "behavior_scan_errors", "capture_drops", "interface_drops",
        "raw_capture_failures", "structured_unparsed_packets", "logger_drops",
        "storage_failures", "suppressed_packets", "recovered_malformed_records"
    };

    public static HealthSnapshot FromRecord(JsonRecord record)
    {
        var status = record.GetString("status") switch
        {
            "healthy" => HealthStatus.Healthy,
            "degraded" => HealthStatus.Degraded,
            "failed" => HealthStatus.Failed,
            _ => HealthStatus.Unknown
        };

        var counters = new Dictionary<string, long>();
        foreach (var key in KnownCounterKeys)
        {
            var value = record.GetLong(key);
            if (value.HasValue) counters[key] = value.Value;
        }

        return new HealthSnapshot
        {
            Status = status,
            ObservedAtUtc = record.EventTimeUtc,
            Final = record.GetBool("final") ?? false,
            EvidenceGap = record.GetBool("evidence_gap") ?? false,
            ResourcePressure = record.GetString("resource_pressure"),
            Counters = counters,
            SchemaVersion = (int?)record.GetLong("schema_version"),
            ComponentId = record.GetString("component_id"),
            SessionId = record.GetString("session_id"),
            Pid = record.GetLong("pid"),
            ExecutableVersion = record.GetString("executable_version"),
            LastError = record.GetString("last_error"),

            EndpointId = record.GetString("endpoint_id"),
            ExecutableHash = record.GetString("executable_hash"),
            StartedAtUnixMs = record.GetLong("started_at"),
            UpdatedAtUnixMs = record.GetLong("updated_at"),
            Collecting = record.GetBool("collecting"),
            PersistenceEnabled = record.GetBool("persistence_enabled"),
            QueueDepth = record.GetLong("queue_depth"),
            QueueCapacity = record.GetLong("queue_capacity"),
            QueuePeak = record.GetLong("queue_peak"),
            RecordsSeen = record.GetLong("records_seen"),
            RecordsWritten = record.GetLong("records_written"),
            RecordsDropped = record.GetLong("records_dropped"),
            ParseFailures = record.GetLong("parse_failures"),
            SourceLoss = record.GetLong("source_loss"),
            WriterFailures = record.GetLong("writer_failures"),
            Rotations = record.GetLong("rotations"),
            RetainedBytes = record.GetLong("retained_bytes"),
            RetainedFiles = record.GetLong("retained_files"),
            ShutdownState = record.GetString("shutdown_state"),
            ShutdownAck = record.GetBool("shutdown_ack")
        };
    }

    /// <summary>FORU.TXT section 5: combines this snapshot with the process running-state and
    /// staleness to produce the full 9-state vocabulary. isRunning/isStopRequested/
    /// healthAgeSeconds/staleThresholdSeconds are supplied by the caller (EndpointHeaderViewModel
    /// already tracks all of these) rather than recomputed here, so there is exactly one place
    /// that decides freshness/session-match (FORU.TXT 6.6) and this method stays a pure function
    /// of already-validated inputs.</summary>
    public static EndpointLifecycleState ClassifyLifecycle(HealthSnapshot? health, bool isRunning,
        bool isStopRequested, bool wasRunningLastObserved, double healthAgeSeconds, double staleThresholdSeconds)
    {
        if (health?.SchemaVersion is { } v && v > MaxKnownSchemaVersion)
            return EndpointLifecycleState.IncompatibleSchema;

        if (!isRunning)
        {
            if (wasRunningLastObserved && !isStopRequested) return EndpointLifecycleState.Crashed;
            return EndpointLifecycleState.Stopped;
        }

        if (isStopRequested) return EndpointLifecycleState.Stopping;
        if (health is null) return EndpointLifecycleState.Starting;
        if (healthAgeSeconds >= staleThresholdSeconds) return EndpointLifecycleState.Stale;

        return health.Status switch
        {
            HealthStatus.Healthy => EndpointLifecycleState.Healthy,
            HealthStatus.Degraded => EndpointLifecycleState.Degraded,
            HealthStatus.Failed => EndpointLifecycleState.Crashed,
            _ => EndpointLifecycleState.Starting
        };
    }
}
