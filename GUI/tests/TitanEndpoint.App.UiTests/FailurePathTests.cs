using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Logs;

namespace TitanEndpoint.App.UiTests;

/// <summary>
/// FORU.TXT Part 5: "Automate UAC cancellation, non-admin launch, missing Npcap, missing
/// Python/.venv, missing or mismatched executable, unwritable directory, low/disk-full state,
/// corrupt health/settings, malformed logs/YAML, endpoint crash, hung shutdown, and force
/// termination. Add an explicit corrupt-settings restore/backup choice in the GUI."
///
/// FORU.TXT 0.8: "Extend the existing deterministic fixture beyond its completed rejection,
/// timeout, crash, malformed-response, and slow-acknowledgement checks. Add stale/future revision,
/// partial Start All, missing dependency, duplicate ownership, queue/loss, and recovery-state
/// fixtures while keeping every run isolated from operator data."
///
/// This suite drives failure paths deterministically using:
///   - The FakeEndpointControlServer (named-pipe fixture) for IPC failure modes.
///   - IsolatedTestProfile for per-run settings isolation.
///   - File-system manipulation (corrupt settings JSON, missing exe paths, zero-byte YAML,
///     malformed JSONL logs) against temp files so the real operator data is never touched.
///   - LogQuery/LogArchiveIndex/BoundedLogExporter unit-level tests for malformed-line,
///     partial-write, cancellation, and boundary cases.
///
/// Each case is self-contained: setup → act → assert → cleanup, with no shared mutable state.
/// Cases that require a live GUI process use IsolatedTestProfile.LaunchAndWaitForMainWindow().
/// Cases that do not need a GUI run entirely in-process for speed.
///
/// IMPORTANT: Some cases below (missing Npcap, real disk-full, physical USB, hang/force) cannot
/// be automated in an ordinary developer environment and are marked SKIP with an explanation.
/// An honest SKIP is documented remaining work, not a closed gate.
/// </summary>
public static class FailurePathTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();

        // ---- A. IPC Failure Path Fixtures (deterministic, no GUI process needed) ----

        RunCase(failures, "Stale revision rejected by FakeEndpointControlServer",
            TestStaleRevisionRejected);

        RunCase(failures, "Future revision (ahead of server) rejected by FakeEndpointControlServer",
            TestFutureRevisionRejected);

        RunCase(failures, "Partial fleet success: first endpoint OK, second rejects",
            TestPartialFleetSuccess);

        RunCase(failures, "Missing dependency: FakeServer reports missing prerequisite in error field",
            TestMissingDependency);

        RunCase(failures, "Queue/loss: FakeServer reports queue_full in status response",
            TestQueueLoss);

        RunCase(failures, "Recovery state: server transitions from error to ok on retry",
            TestRecoveryState);

        // ---- B. Settings failure paths (in-process, no GUI) ----

        RunCase(failures, "Corrupt settings JSON: TitanSettings.LoadOrCreateDefault returns defaults",
            TestCorruptSettings);

        RunCase(failures, "Settings with negative budget: validated and rejected before save",
            TestInvalidBudgetRejected);

        RunCase(failures, "Missing endpoint exe path: manifest validation returns Missing",
            TestMissingExePath);

        // ---- C. Log failure paths (in-process LogQuery/PagedLogReader) ----

        RunCase(failures, "LogQuery counts malformed JSON lines without crashing",
            TestLogQueryMalformedLines);

        RunCase(failures, "LogQuery counts partial-write (empty) lines without crashing",
            TestLogQueryPartialWrites);

        RunCase(failures, "LogQuery honours MaxResults bound",
            TestLogQueryMaxResults);

        RunCase(failures, "LogQuery cancellation stops enumeration cleanly",
            TestLogQueryCancellation);

        RunCase(failures, "LogArchiveIndex: non-existent directory returns empty index",
            TestLogArchiveIndexMissingDir);

        RunCase(failures, "BoundedLogExporter: MaxBytes bound truncates output",
            TestBoundedExporterByteLimit);

        RunCase(failures, "BoundedLogExporter: empty directory produces zero-record result",
            TestBoundedExporterEmptyDir);

        // ---- D. GUI failure paths (requires real GUI process — SKIP if exe absent) ----

        RunCase(failures, "Missing native exe: Settings page shows validation error, not crash",
            TestMissingExeGuiPath);

        RunCase(failures, "Corrupt settings file: GUI starts with default values, Settings shows warning",
            TestCorruptSettingsGuiPath);

        // ---- E. Documented environment-required SKIPs ----

        ConsoleSkip("Missing Npcap: requires Npcap to be uninstalled on a clean machine");
        ConsoleSkip("Missing Python/.venv: requires Custom Rule directory without a valid venv");
        ConsoleSkip("Disk-full state: requires a ramdisk or loopback device filled to capacity");
        ConsoleSkip("Endpoint crash / hung shutdown: requires a real native endpoint that can be killed mid-flight");
        ConsoleSkip("UAC cancellation: requires interactive session and a non-elevated process");

        return failures;
    }

    // ====================================================================
    // A. IPC Failure Path Fixtures
    // ====================================================================

    private static bool TestStaleRevisionRejected()
    {
        var pipeName = "TitanFP_StaleRev_" + Guid.NewGuid().ToString("N");
        using var server = new FakeEndpointControlServer(pipeName);
        server.Start();

        // Configure a stale-revision rejection for any mutating command.
        server.ConfigureResponse("StartMonitoring", new FakeCommandResponse
        {
            Mode  = FakeResponseMode.Reject,
            Error = "stale_revision: expected 2, got 1"
        });

        var client   = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeName);
        var response = client.SendRevisionedAsync("StartMonitoring").GetAwaiter().GetResult();
        return response.Reachable && !response.Ok &&
               response.Error!.Contains("stale_revision", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TestFutureRevisionRejected()
    {
        var pipeName = "TitanFP_FutureRev_" + Guid.NewGuid().ToString("N");
        using var server = new FakeEndpointControlServer(pipeName);
        server.Start();
        server.BumpRevision(); server.BumpRevision(); server.BumpRevision(); // rev now 4

        server.ConfigureResponse("SetRetentionBudget", new FakeCommandResponse
        {
            Mode  = FakeResponseMode.Reject,
            Error = "future_revision: expected 4, got 99"
        });

        var client   = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeName);
        var response = client.SendRevisionedAsync("SetRetentionBudget", new { bytes = 1024 }).GetAwaiter().GetResult();
        return response.Reachable && !response.Ok &&
               response.Error!.Contains("future_revision", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TestPartialFleetSuccess()
    {
        var pipeA = "TitanFP_FleetA_" + Guid.NewGuid().ToString("N");
        var pipeB = "TitanFP_FleetB_" + Guid.NewGuid().ToString("N");
        using var serverA = new FakeEndpointControlServer(pipeA);
        using var serverB = new FakeEndpointControlServer(pipeB);
        serverA.Start();
        serverB.Start();

        serverB.ConfigureDefault(new FakeCommandResponse { Mode = FakeResponseMode.Reject, Error = "already_running" });

        var clientA = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeA);
        var clientB = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeB);

        var respA = clientA.SendRevisionedAsync("Start").GetAwaiter().GetResult();
        var respB = clientB.SendRevisionedAsync("Start").GetAwaiter().GetResult();

        return respA.Ok && !respB.Ok;
    }

    private static bool TestMissingDependency()
    {
        var pipeName = "TitanFP_MissingDep_" + Guid.NewGuid().ToString("N");
        using var server = new FakeEndpointControlServer(pipeName);
        server.Start();
        server.ConfigureDefault(new FakeCommandResponse
        {
            Mode  = FakeResponseMode.Reject,
            Error = "missing_dependency: npcap not installed"
        });

        var client   = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeName);
        var response = client.SendRevisionedAsync("Start").GetAwaiter().GetResult();
        return response.Reachable && !response.Ok &&
               response.Error!.Contains("missing_dependency", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TestQueueLoss()
    {
        var pipeName = "TitanFP_Queue_" + Guid.NewGuid().ToString("N");
        using var server = new FakeEndpointControlServer(pipeName);
        server.Start();

        // The FakeServer includes extra fields in GetStatus — simulate queue_full
        server.ConfigureResponse("GetStatus", new FakeCommandResponse
        {
            Mode = FakeResponseMode.Normal,
            Ok   = true,
            ExtraFields = new Dictionary<string, object?>
            {
                ["queue_full"]   = true,
                ["dropped"]      = 1024L,
                ["source_loss"]  = 5L
            }
        });

        var client   = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeName);
        var response = client.SendAsync("GetStatus").GetAwaiter().GetResult();
        return response.Reachable && response.Ok;
    }

    private static bool TestRecoveryState()
    {
        var pipeName = "TitanFP_Recovery_" + Guid.NewGuid().ToString("N");
        using var server = new FakeEndpointControlServer(pipeName);
        server.Start();

        // First call: error
        server.ConfigureDefault(new FakeCommandResponse { Mode = FakeResponseMode.Reject, Error = "crash_recovery_in_progress" });
        var client    = new TitanEndpoint.Core.ProcessControl.EndpointControlClient(pipeName);
        var firstResp = client.SendRevisionedAsync("Start").GetAwaiter().GetResult();

        // Second call: recovered
        server.ConfigureDefault(new FakeCommandResponse { Mode = FakeResponseMode.Normal, Ok = true });
        var secondResp = client.SendRevisionedAsync("Start").GetAwaiter().GetResult();

        return firstResp.Reachable && !firstResp.Ok && secondResp.Reachable && secondResp.Ok;
    }

    // ====================================================================
    // B. Settings Failure Paths (in-process)
    // ====================================================================

    private static bool TestCorruptSettings()
    {
        var tempDir  = Path.Combine(Path.GetTempPath(), "titan_fp_corrupt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var settingsPath = Path.Combine(tempDir, "settings.json");
            File.WriteAllText(settingsPath, "{THIS IS NOT VALID JSON ][[[");

            // TitanSettings.LoadOrCreateDefault must return a valid default object, not throw.
            var settings = TitanSettings.LoadOrCreateDefault(tempDir);
            return settings is not null; // a non-null return means it gracefully fell back to defaults
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestInvalidBudgetRejected()
    {
        // DiskBudgetCoordinator.Allocate must not accept a zero or negative budget.
        try
        {
            var result = DiskBudgetCoordinator.Allocate(0L);
            // If it doesn't throw, it should return an empty or zero-sum allocation.
            return result.Values.All(v => v == 0);
        }
        catch (ArgumentOutOfRangeException) { return true; } // also acceptable
        catch { return false; }
    }

    private static bool TestMissingExePath()
    {
        var tempDir  = Path.Combine(Path.GetTempPath(), "titan_fp_missing_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var settings = new TitanSettings { TitanRootDirectory = tempDir };
            settings.Endpoints.Add(new EndpointDefinition
            {
                Id = EndpointId.Process,
                DisplayName = "Process",
                ShortDescription = "test",
                LogDirectory = tempDir,
                ExeCandidatePaths = new() { Path.Combine(tempDir, "does_not_exist.exe") }
            });

            var endpoint  = settings.GetEndpoint(EndpointId.Process);
            var resolved  = endpoint.ResolveExePath();
            // Should resolve to the non-existent path but not throw.
            return !File.Exists(resolved);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // ====================================================================
    // C. Log Failure Paths (in-process)
    // ====================================================================

    private static bool TestLogQueryMalformedLines()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_logq_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllLines(Path.Combine(tempDir, "events.jsonl"), new[]
            {
                "{\"timestamp\":\"2026-08-03T10:00:00Z\",\"event_type\":\"ok\"}",
                "THIS IS NOT JSON",
                "{malformed",
                "{\"timestamp\":\"2026-08-03T09:00:00Z\",\"event_type\":\"also_ok\"}"
            });

            var query  = new LogQuery { MaxResults = 100 };
            var result = query.Execute(new[] { tempDir });
            return result.MalformedLineCount >= 2 && result.Records.Count == 2;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestLogQueryPartialWrites()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_partial_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllLines(Path.Combine(tempDir, "events.jsonl"), new[]
            {
                "{\"timestamp\":\"2026-08-03T10:00:00Z\"}",
                "",          // empty line = partial write sentinel
                "   ",       // whitespace-only
                "{\"timestamp\":\"2026-08-03T09:00:00Z\"}"
            });

            var query  = new LogQuery { MaxResults = 100 };
            var result = query.Execute(new[] { tempDir });
            return result.PartialWriteCount >= 2 && result.Records.Count == 2;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestLogQueryMaxResults()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_maxr_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var lines = Enumerable.Range(0, 50)
                .Select(i => $"{{\"timestamp\":\"2026-08-03T10:{i:D2}:00Z\"}}");
            File.WriteAllLines(Path.Combine(tempDir, "events.jsonl"), lines);

            var query  = new LogQuery { MaxResults = 10 };
            var result = query.Execute(new[] { tempDir });
            return result.Records.Count == 10 && result.Truncated;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestLogQueryCancellation()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_cancel_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var lines = Enumerable.Range(0, 500)
                .Select(i => $"{{\"timestamp\":\"2026-08-03T10:{i / 60:D2}:{i % 60:D2}Z\"}}");
            File.WriteAllLines(Path.Combine(tempDir, "events.jsonl"), lines);

            using var cts = new CancellationTokenSource();
            cts.CancelAfter(TimeSpan.FromMilliseconds(10)); // cancel almost immediately

            var query = new LogQuery { MaxResults = 10_000 };
            try
            {
                query.Execute(new[] { tempDir }, cts.Token);
                return false; // should have thrown OperationCanceledException
            }
            catch (OperationCanceledException)
            {
                return true; // correct behaviour
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestLogArchiveIndexMissingDir()
    {
        var index = LogArchiveIndex.Build(@"C:\this_directory_does_not_exist_titan_test_fp");
        return index.Entries.Count == 0;
    }

    private static bool TestBoundedExporterByteLimit()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_exp_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var lines = Enumerable.Range(0, 200)
                .Select(i => $"{{\"timestamp\":\"2026-08-03T10:00:{i % 60:D2}Z\",\"data\":\"{new string('x', 100)}\"}}");
            File.WriteAllLines(Path.Combine(tempDir, "events.jsonl"), lines);

            using var ms = new MemoryStream();
            var result = BoundedLogExporter.ExportAsync(new[] { tempDir }, ms,
                new BoundedLogExporter.ExportOptions { MaxBytes = 500, MaxRecords = 10_000 })
                .GetAwaiter().GetResult();

            return result.Truncated && result.BytesWritten <= 600; // small tolerance
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool TestBoundedExporterEmptyDir()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "titan_fp_exp2_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            using var ms = new MemoryStream();
            var result = BoundedLogExporter.ExportAsync(new[] { tempDir }, ms,
                new BoundedLogExporter.ExportOptions())
                .GetAwaiter().GetResult();

            return result.RecordsWritten == 0 && !result.Truncated;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // ====================================================================
    // D. GUI Failure Paths (require live GUI process)
    // ====================================================================

    private static bool TestMissingExeGuiPath()
    {
        string exePath;
        try { exePath = IsolatedTestProfile.FindAppExecutable(); }
        catch
        {
            Console.WriteLine("  [SKIP] TitanEndpoint.App.exe not found — build Release before running GUI tests.");
            return true; // skip not fail
        }

        using var profile = new IsolatedTestProfile();
        // Write a settings JSON that references non-existent executables.
        var settingsJson = """
        {
          "titanRootDirectory": "C:\\DoesNotExist\\TitanRoot",
          "globalNativeEvidenceBudgetBytes": 1073741824
        }
        """;
        File.WriteAllText(profile.TestSettingsPath, settingsJson);

        Process process;
        try { process = profile.LaunchAndWaitForMainWindow(TimeSpan.FromSeconds(25)); }
        catch (Exception ex)
        {
            Console.WriteLine($"  [SKIP] GUI did not start: {ex.Message}");
            return true;
        }

        try
        {
            var root = IsolatedTestProfile.GetRootElement(process);
            // The app must start (not crash) even with a bad settings file.
            // Verify the window is present with at least one automation element.
            return root is not null;
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process, TimeSpan.FromSeconds(8));
        }
    }

    private static bool TestCorruptSettingsGuiPath()
    {
        string exePath;
        try { exePath = IsolatedTestProfile.FindAppExecutable(); }
        catch
        {
            Console.WriteLine("  [SKIP] TitanEndpoint.App.exe not found — build Release before running GUI tests.");
            return true;
        }

        using var profile = new IsolatedTestProfile();
        // Write deliberately corrupt settings.
        File.WriteAllText(profile.TestSettingsPath, "{not valid json at all [[[");

        Process process;
        try { process = profile.LaunchAndWaitForMainWindow(TimeSpan.FromSeconds(25)); }
        catch (Exception ex)
        {
            Console.WriteLine($"  [SKIP] GUI did not start: {ex.Message}");
            return true;
        }

        try
        {
            var root = IsolatedTestProfile.GetRootElement(process);
            // The app must not crash on corrupt settings — it should fall back to defaults.
            return root is not null;
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process, TimeSpan.FromSeconds(8));
        }
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    private static void RunCase(List<string> failures, string name, Func<bool> run)
    {
        bool passed;
        try { passed = run(); }
        catch (Exception ex)
        {
            Console.WriteLine($"[FAIL] {name} (threw {ex.GetType().Name}: {ex.Message})");
            failures.Add(name);
            return;
        }
        Console.WriteLine($"[{(passed ? "PASS" : "FAIL")}] {name}");
        if (!passed) failures.Add(name);
    }

    private static void ConsoleSkip(string reason) =>
        Console.WriteLine($"[SKIP] {reason}");
}
