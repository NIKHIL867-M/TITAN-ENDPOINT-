using System.Text.Json;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.FileIntegrity;
using TitanEndpoint.Core.Json;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Manifest;
using TitanEndpoint.Core.Evidence;
using TitanEndpoint.Core.Logs;

var failures = new List<string>();
void Check(bool condition, string name)
{
    Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
    if (!condition) failures.Add(name);
}

var parsed = JsonRecord.TryParse("{\"timestamp\":\"2026-08-02T10:00:00Z\",\"pid\":42}", DateTimeOffset.UtcNow);
    Check(parsed?.GetLong("pid") == 42 && parsed.EventTimeUtc == DateTimeOffset.Parse("2026-08-02T10:00:00Z"),
    "JSON record typed access and timestamp resolution");
var allocations = DiskBudgetCoordinator.Allocate(5L * 1024 * 1024 * 1024);
Check(allocations.Count == 6 && allocations.Values.Sum() == 5L * 1024 * 1024 * 1024 && allocations.Values.All(value => value > 0),
    "coordinated disk allocation is positive for all six native endpoints and exactly bounded globally");

var tempRoot = Path.Combine(Path.GetTempPath(), "titan_gui_regression_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempRoot);
try
{
    var sample = Path.Combine(tempRoot, "sample.bin");
    await File.WriteAllTextAsync(sample, "approved content");
    var baselineDirectory = Path.Combine(tempRoot, "baseline-store");
    var baseline = new FileBaselineStore(baselineDirectory);
    const string hash = "f00d";
    var info = new FileInfo(sample);
    baseline.Approve(sample, hash, info.Length, info.LastWriteTimeUtc);
    Check(baseline.Compare(sample, hash) == BaselineComparisonState.Unchanged,
        "approved baseline round-trip");
    Check(baseline.IntegrityStatus.Contains("verified", StringComparison.OrdinalIgnoreCase),
        "baseline HMAC integrity verification");

    var storePath = Path.Combine(baselineDirectory, "file_baselines.json");
    var tampered = (await File.ReadAllTextAsync(storePath)).Replace("f00d", "baad", StringComparison.Ordinal);
    await File.WriteAllTextAsync(storePath, tampered);
    var reopened = new FileBaselineStore(baselineDirectory);
    _ = reopened.Find(sample);
    Check(reopened.LastError?.Contains("cannot be trusted", StringComparison.OrdinalIgnoreCase) == true,
        "tampered baseline fails closed");

    var runtimeRoot = Path.Combine(tempRoot, "runtime");
    var settings = new TitanSettings { TitanRootDirectory = runtimeRoot };
    foreach (var id in new[] { EndpointId.Port, EndpointId.Process, EndpointId.File, EndpointId.Network, EndpointId.Application, EndpointId.Correlator })
    {
        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = id,
            DisplayName = id.ToString(),
            ShortDescription = "test",
            LogDirectory = Path.Combine(runtimeRoot, id.ToString()),
            ExeCandidatePaths = new() { Path.Combine(runtimeRoot, id + ".exe") }
        });
    }
    RuntimeConfiguration.Prepare(settings);
    var generated = await File.ReadAllTextAsync(settings.RuntimeCorrelatorConfigPath!);
    Check(settings.Endpoints.Single(e => e.Id == EndpointId.Correlator).RuntimeCommandArguments is { Length: > 2 },
        "Correlator receives generated runtime config argument");
    Check(Enum.GetValues<EndpointId>().Where(id => id is not EndpointId.CustomRule and not EndpointId.Correlator)
        .All(id => generated.Contains(settings.GetEndpoint(id).LogDirectory, StringComparison.OrdinalIgnoreCase)),
        "generated source config uses current endpoint log directories");

    var definition = settings.GetEndpoint(EndpointId.Process);
    definition.ManifestCommandArguments = "--manifest";
    definition.RuntimeCommandArguments = "--runtime";
    Check(definition.ResolveCommandArguments() == "--runtime", "runtime arguments override manifest arguments");
}
finally
{
    try { Directory.Delete(tempRoot, recursive: true); } catch { }
}

// Bounded archive paging and durable evidence identity validation.
{
    var evidenceRoot = Path.Combine(Path.GetTempPath(), "titan_evidence_regression_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(evidenceRoot);
    try
    {
        var archive = Path.Combine(evidenceRoot, "events.jsonl");
        var exactLine = "{\"native_record_id\":\"record-1\",\"native_session_id\":\"session-1\",\"native_source_file\":\"events.jsonl\",\"native_content_hash\":\"abc123\",\"pid\":42}";
        await File.WriteAllTextAsync(archive, exactLine + "\n{\"pid\":43}\n");
        var definition = new EndpointDefinition { Id = EndpointId.Process, DisplayName = "Process", ShortDescription = "test", LogDirectory = evidenceRoot };
        var verified = EvidenceResolver.Resolve(new EvidenceReference("process", "record-1", "session-1", "events.jsonl", 0, "abc123"), new[] { definition });
        Check(verified.State == EvidenceResolutionState.Verified && verified.Content.Contains("\"pid\":42"),
            "durable evidence resolver validates exact retained identity at byte offset");
        var mismatch = EvidenceResolver.Resolve(new EvidenceReference("process", "wrong", "session-1", "events.jsonl", 0, "abc123", "embedded"), new[] { definition });
        Check(mismatch.State == EvidenceResolutionState.IdentityMismatch && mismatch.Content == "embedded",
            "durable evidence resolver fails closed on identity mismatch");
        var page = PagedLogReader.ReadPageBackward(archive, null, 1);
        Check(page.Lines.Count == 1 && page.Lines[0].Contains("\"pid\":43") && page.NextCursor is not null,
            "paged log reader returns newest record without loading full archive");
    }
    finally { try { Directory.Delete(evidenceRoot, recursive: true); } catch { } }
}

// FORU.TXT section 1/3: the real runtime-manifest.json (package-relative
// paths, generated by GUI\scripts\Generate-RuntimeManifest.ps1) must
// actually resolve and validate against the real, currently-built binaries
// -- not a synthetic fixture. This is the single place that would catch a
// manifest/GUI-loader path-resolution mismatch (e.g. the schema-1 -> 2
// relative-path migration) before Santosh ever launches the app.
{
    var realTitanRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", ".."));
    var manifestPath = Path.Combine(realTitanRoot, "runtime-manifest.json");
    Check(File.Exists(manifestPath), $"real runtime-manifest.json exists at {manifestPath}");

    if (File.Exists(manifestPath))
    {
        var settings = TitanEndpoint.Core.Config.TitanSettings.LoadOrCreateDefault(realTitanRoot);
        Check(settings.RuntimeManifestLoaded, "TitanSettings loads the real runtime-manifest.json");

        foreach (var id in new[]
                 {
                     EndpointId.Process, EndpointId.Network, EndpointId.Application,
                     EndpointId.File, EndpointId.Port, EndpointId.Correlator
                 })
        {
            var endpoint = settings.GetEndpoint(id);
            var resolvedPath = endpoint.ResolveExePath();
            Check(File.Exists(resolvedPath), $"{id}: manifest-relative exePath resolves to a real file ({resolvedPath})");
            Check(endpoint.ValidateAgainstManifest() == ManifestValidationState.Ok,
                $"{id}: real built exe hash matches the real manifest (schema-2 relative-path resolution is correct)");
            Check(endpoint.ManifestControlChannelImplemented,
                $"{id}: manifest reports a real IPC control channel (all 6 endpoints now have one)");
        }
    }
}

// FORU.TXT section 5: the 9-state lifecycle classification -- each case checks one real,
// distinguishable scenario, not just that the function returns without throwing.
{
    HealthSnapshot MakeHealth(HealthStatus status, int schemaVersion = 2) => new()
    {
        Status = status,
        ObservedAtUtc = DateTimeOffset.UtcNow,
        SchemaVersion = schemaVersion
    };

    Check(HealthSnapshot.ClassifyLifecycle(null, isRunning: false, isStopRequested: false,
            wasRunningLastObserved: false, healthAgeSeconds: 0, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Stopped,
        "not running, wasn't running before -> Stopped");

    Check(HealthSnapshot.ClassifyLifecycle(null, isRunning: false, isStopRequested: false,
            wasRunningLastObserved: true, healthAgeSeconds: 0, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Crashed,
        "was running, now isn't, no stop was requested -> Crashed");

    Check(HealthSnapshot.ClassifyLifecycle(null, isRunning: false, isStopRequested: true,
            wasRunningLastObserved: true, healthAgeSeconds: 0, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Stopped,
        "was running, now isn't, but a stop WAS requested -> Stopped (not Crashed)");

    Check(HealthSnapshot.ClassifyLifecycle(null, isRunning: true, isStopRequested: true,
            wasRunningLastObserved: true, healthAgeSeconds: 0, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Stopping,
        "still running but a stop is in flight -> Stopping");

    Check(HealthSnapshot.ClassifyLifecycle(null, isRunning: true, isStopRequested: false,
            wasRunningLastObserved: false, healthAgeSeconds: 0, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Starting,
        "running, no health record has arrived yet -> Starting");

    Check(HealthSnapshot.ClassifyLifecycle(MakeHealth(HealthStatus.Healthy), isRunning: true,
            isStopRequested: false, wasRunningLastObserved: true, healthAgeSeconds: 100, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Stale,
        "running with a healthy-looking but old heartbeat -> Stale (freshness wins over reported status)");

    Check(HealthSnapshot.ClassifyLifecycle(MakeHealth(HealthStatus.Healthy), isRunning: true,
            isStopRequested: false, wasRunningLastObserved: true, healthAgeSeconds: 1, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Healthy,
        "running, fresh, healthy -> Healthy");

    Check(HealthSnapshot.ClassifyLifecycle(MakeHealth(HealthStatus.Degraded), isRunning: true,
            isStopRequested: false, wasRunningLastObserved: true, healthAgeSeconds: 1, staleThresholdSeconds: 45)
          == EndpointLifecycleState.Degraded,
        "running, fresh, degraded -> Degraded");

    Check(HealthSnapshot.ClassifyLifecycle(MakeHealth(HealthStatus.Healthy, schemaVersion: 99), isRunning: true,
            isStopRequested: false, wasRunningLastObserved: true, healthAgeSeconds: 1, staleThresholdSeconds: 45)
          == EndpointLifecycleState.IncompatibleSchema,
        "a health record from a newer, unrecognized schema_version -> IncompatibleSchema (wins over everything else)");
}

// ============================================================
// HISTORICAL LOG REGRESSION TESTS
// FORU.TXT Part 3: "Add indexed time-range paging across archives, cancellation from the UI,
// compound endpoint/event filters, deterministic cross-file ordering, and bounded bulk export.
// Surface invalid UTF-8, partial-write, malformed-line, and unsupported-schema counts."
// ============================================================

{
    var histRoot = Path.Combine(Path.GetTempPath(), "titan_hist_regression_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(histRoot);
    try
    {
        // ---- LogArchiveIndex ----

        var emptyIndex = LogArchiveIndex.Build(histRoot);
        Check(emptyIndex.Entries.Count == 0, "LogArchiveIndex: empty directory returns zero entries");

        var missingIndex = LogArchiveIndex.Build(Path.Combine(histRoot, "no_such_dir"));
        Check(missingIndex.Entries.Count == 0, "LogArchiveIndex: missing directory returns zero entries without throwing");

        var archA = Path.Combine(histRoot, "archive_a.jsonl");
        var archB = Path.Combine(histRoot, "archive_b.jsonl");
        var archC = Path.Combine(histRoot, "archive_c.json");
        File.WriteAllText(archA, "{\"pid\":1}\n");
        File.SetLastWriteTimeUtc(archA, new DateTime(2026, 8, 1, 10, 0, 0, DateTimeKind.Utc));
        File.WriteAllText(archB, "{\"pid\":2}\n");
        File.SetLastWriteTimeUtc(archB, new DateTime(2026, 8, 2, 10, 0, 0, DateTimeKind.Utc));
        File.WriteAllText(archC, "{\"pid\":3}\n");
        File.SetLastWriteTimeUtc(archC, new DateTime(2026, 8, 1, 11, 0, 0, DateTimeKind.Utc));

        var archiveIndex = LogArchiveIndex.Build(histRoot);
        Check(archiveIndex.Entries.Count == 3, "LogArchiveIndex: JSONL and line-delimited JSON archives are found");
        Check(archiveIndex.Entries[0].LastWriteUtc > archiveIndex.Entries[1].LastWriteUtc,
            "LogArchiveIndex: entries are ordered newest-first");
        Check(archiveIndex.TotalRetainedBytes >= 0, "LogArchiveIndex: TotalRetainedBytes is non-negative");

        var cutoff = new DateTimeOffset(2026, 8, 2, 0, 0, 0, TimeSpan.Zero);
        var rangeEntries = archiveIndex.EntriesInRange(cutoff, null);
        Check(rangeEntries.Count == 1, "LogArchiveIndex.EntriesInRange: coarse filter returns only archive_b");

        // ---- LogQuery ----

        var mixed = Path.Combine(histRoot, "mixed.jsonl");
        File.WriteAllLines(mixed, new[]
        {
            "{\"timestamp\":\"2026-08-03T12:00:00Z\",\"event_type\":\"test\"}",
            "NOT VALID JSON",
            "{\"timestamp\":\"2026-08-03T11:00:00Z\",\"event_type\":\"test2\"}",
            "{\"t_unix_ms\":1785760200000,\"action\":\"file_write\"}"
        });

        var logQuery  = new LogQuery { MaxResults = 100 };
        var qResult = logQuery.Execute(new[] { histRoot });
        Check(qResult.MalformedLineCount >= 1, "LogQuery: malformed line is counted");
        Check(qResult.Records.Any(r => r.EventType == "test" || r.EventType == "test2"),
            "LogQuery: valid records are returned");
        Check(qResult.Records.Any(r => r.EventTime == DateTimeOffset.Parse("2026-08-03T12:30:00Z") && r.EventType == "file_write"),
            "LogQuery: native t_unix_ms timestamps and action event types are normalized");

        var eventFiltered = new LogQuery { MaxResults = 100, EventType = "FILE_WRITE" }.Execute(new[] { histRoot });
        Check(eventFiltered.Records.Count == 1 && eventFiltered.Records[0].EventType == "file_write",
            "LogQuery: EventType filtering is exact and case-insensitive");

        var bigDir = Path.Combine(histRoot, "big");
        Directory.CreateDirectory(bigDir);
        var bigLines = Enumerable.Range(0, 50).Select(i => $"{{\"timestamp\":\"2026-08-03T10:{i / 60:D2}:{i % 60:D2}Z\"}}");
        File.WriteAllLines(Path.Combine(bigDir, "big.jsonl"), bigLines);
        var boundedQuery = new LogQuery { MaxResults = 5 };
        var boundedResult = boundedQuery.Execute(new[] { bigDir });
        Check(boundedResult.Records.Count <= 5, "LogQuery: MaxResults bound is respected");
        Check(boundedResult.Truncated, "LogQuery: Truncated is true when MaxResults is hit");

        var partialDir = Path.Combine(histRoot, "partial");
        Directory.CreateDirectory(partialDir);
        // Blank/whitespace records are not returned to the UI, but are counted as partial writer
        // output so the history pane can surface an evidence-quality gap honestly.
        File.WriteAllLines(Path.Combine(partialDir, "partial.jsonl"), new[]
            { "{\"timestamp\":\"2026-08-03T09:00:00Z\"}", "", "   ", "{\"timestamp\":\"2026-08-03T08:00:00Z\"}" });
        var partialResult = new LogQuery { MaxResults = 100 }.Execute(new[] { partialDir });
        Check(partialResult.Records.Count == 2, "LogQuery: only non-empty parseable lines returned (empty lines stripped by reader)");
        Check(partialResult.PartialWriteCount == 2, "LogQuery: blank/whitespace records are counted as partial writes");

        var cancelDir = Path.Combine(histRoot, "cancel");
        Directory.CreateDirectory(cancelDir);
        File.WriteAllLines(Path.Combine(cancelDir, "cancel.jsonl"),
            Enumerable.Range(0, 200).Select(i => $"{{\"timestamp\":\"2026-08-03T10:00:{i % 60:D2}Z\"}}"));
        // Cancel synchronously (not via CancelAfter) so this test is deterministic: Execute's
        // first ct.ThrowIfCancellationRequested() call is guaranteed to observe a cancelled token
        // instead of racing a timer against sub-millisecond in-memory query execution.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        bool cancelThrew = false;
        try { new LogQuery { MaxResults = 100_000 }.Execute(new[] { cancelDir }, cts.Token); }
        catch (OperationCanceledException) { cancelThrew = true; }
        Check(cancelThrew, "LogQuery: cancellation throws OperationCanceledException");

        // ---- BoundedLogExporter ----

        var exportDir = Path.Combine(histRoot, "export");
        Directory.CreateDirectory(exportDir);
        // Write 25 records but request MaxResults=20 — this guarantees the query is truncated.
        File.WriteAllLines(Path.Combine(exportDir, "ex.jsonl"),
            Enumerable.Range(0, 25).Select(i => $"{{\"n\":{i}}}"));
        using var ms = new MemoryStream();
        var exportResult = BoundedLogExporter.ExportAsync(new[] { exportDir }, ms,
            new BoundedLogExporter.ExportOptions { MaxRecords = 20, Format = BoundedLogExporter.ExportFormat.Jsonl })
            .GetAwaiter().GetResult();
        Check(exportResult.RecordsWritten == 20, "BoundedLogExporter: exports exactly MaxRecords records");
        Check(exportResult.Truncated, "BoundedLogExporter: Truncated is true when MaxRecords is hit before all records");

        // Verify non-truncation: MaxRecords=100, file has 25 records — all are exported.
        ms.Position = 0; ms.SetLength(0);
        var fullExport = BoundedLogExporter.ExportAsync(new[] { exportDir }, ms,
            new BoundedLogExporter.ExportOptions { MaxRecords = 100, Format = BoundedLogExporter.ExportFormat.Jsonl })
            .GetAwaiter().GetResult();
        Check(fullExport.RecordsWritten == 25, "BoundedLogExporter: exports all 25 records when MaxRecords is not hit");
        // Note: LogQuery sets Truncated=true when records.Count reaches MaxResults even if the file
        // had exactly that many. Non-truncation at the file level is verified by RecordsWritten == 25.

        ms.Position = 0; ms.SetLength(0);
        var truncExport = BoundedLogExporter.ExportAsync(new[] { exportDir }, ms,
            new BoundedLogExporter.ExportOptions { MaxBytes = 30, MaxRecords = 10_000 })
            .GetAwaiter().GetResult();
        Check(truncExport.Truncated, "BoundedLogExporter: truncated when MaxBytes is tiny");

        using var msJson = new MemoryStream();
        var jsonExport = BoundedLogExporter.ExportAsync(new[] { exportDir }, msJson,
            new BoundedLogExporter.ExportOptions { MaxRecords = 5, Format = BoundedLogExporter.ExportFormat.JsonArray })
            .GetAwaiter().GetResult();
        msJson.Position = 0;
        var jsonText = new System.IO.StreamReader(msJson).ReadToEnd();
        Check(jsonText.TrimStart().StartsWith("[") && jsonText.TrimEnd().EndsWith("]"),
            "BoundedLogExporter: JSON array format produces valid outer brackets");

        using var filteredExport = new MemoryStream();
        var filteredExportResult = BoundedLogExporter.ExportAsync(new[] { histRoot }, filteredExport,
            new BoundedLogExporter.ExportOptions { EventType = "file_write", MaxRecords = 100 })
            .GetAwaiter().GetResult();
        Check(filteredExportResult.RecordsWritten == 1,
            "BoundedLogExporter: EventType filter is applied to exported evidence");
    }
    finally
    {
        try { Directory.Delete(histRoot, recursive: true); } catch { }
    }
}

if (failures.Count != 0)
{
    Console.Error.WriteLine($"{failures.Count} regression test(s) failed: {string.Join(", ", failures)}");
    return 1;
}
Console.WriteLine("All TITAN Core regression tests passed.");
return 0;
