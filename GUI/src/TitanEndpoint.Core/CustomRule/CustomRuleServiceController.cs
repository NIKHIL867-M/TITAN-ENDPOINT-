using System.Diagnostics;
using System.Text;
using System.Text.Json;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.Core.CustomRule;

/// <summary>
/// Lifecycle control for CUSTOM RULE's two background processes — the FastAPI service and the
/// watcher — for Start All / Stop All (FORU.TXT section 3: "...-&gt; Custom Rule service/watcher"
/// and section 13.8: "Wire the local Custom Rule service and watcher into Start All/Stop All").
/// Deliberately does NOT launch CUSTOM RULE\desktop.py itself — that opens its own Qt GUI window,
/// which isn't what "Start All" from TITAN's own GUI should trigger. Instead launches the API and
/// watcher directly via this project's own .venv Python, headless, the same two subprocesses
/// desktop.py itself would otherwise start.
/// </summary>
public sealed class CustomRuleServiceController
{
    private readonly string _customRuleRoot;
    private readonly CustomRuleApiClient _apiClient;
    private readonly string? _correlatorConfigPath;
    private readonly string? _correlatorLogDirectory;
    private Process? _apiProcess; // only set if THIS controller started it this session
    private Process? _watcherProcess; // only set when THIS controller starts it

    public CustomRuleServiceController(string customRuleRoot, CustomRuleApiClient apiClient,
        string? correlatorConfigPath = null, string? correlatorLogDirectory = null)
    {
        _customRuleRoot = customRuleRoot;
        _apiClient = apiClient;
        _correlatorConfigPath = correlatorConfigPath;
        _correlatorLogDirectory = correlatorLogDirectory;
    }

    private string PythonExePath => Path.Combine(_customRuleRoot, ".venv", "Scripts", "python.exe");
    private string WatcherPidFile => Path.Combine(_customRuleRoot, "data", "watcher.pid");
    private string WatcherRuntimeFile => Path.Combine(_customRuleRoot, "data", "watcher_runtime.json");

    public bool IsWatcherRunning(out int pid)
    {
        pid = 0;
        if (!File.Exists(WatcherPidFile)) return false;
        try
        {
            if (!int.TryParse(File.ReadAllText(WatcherPidFile).Trim(), out pid)) return false;
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return false;

            // Windows PIDs are reused over time -- a stale pid file whose PID has since been
            // recycled by an unrelated process must not be treated as "the watcher is running."
            // Verify the image is at least a python(w).exe, the same identity check pattern
            // Section 2's ProcessImagePath establishes for the native collectors (a full
            // cmdline/"watcher.main" check like desktop.py's own psutil-based _watcher_running
            // would be stronger, but .NET has no built-in cmdline accessor without WMI).
            var imagePath = TryGetImagePath(p);
            if (imagePath is null) return true; // couldn't verify either way -- don't false-negative on a real watcher
            var fileName = Path.GetFileName(imagePath);
            return string.Equals(fileName, "python.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(fileName, "pythonw.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        {
            return false; // pid file unreadable, or that PID isn't a real running process anymore
        }
    }

    private static string? TryGetImagePath(Process p)
    {
        try { return p.MainModule?.FileName; }
        catch (System.ComponentModel.Win32Exception) { return ProcessImagePath.TryGetImagePath(p.Id); }
        catch (InvalidOperationException) { return null; }
    }

    public (bool Ok, string Message) StartWatcher()
    {
        if (IsWatcherRunning(out _)) return (true, "Watcher already running.");
        if (!File.Exists(PythonExePath))
            return (false, $"Python virtual environment not found at {PythonExePath}. Run CUSTOM RULE's setup first.");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = PythonExePath,
                Arguments = "-m watcher.main",
                WorkingDirectory = _customRuleRoot,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            if (!string.IsNullOrWhiteSpace(_correlatorConfigPath))
                psi.Environment["TITAN_CORRELATOR_CONFIG"] = _correlatorConfigPath;
            if (!string.IsNullOrWhiteSpace(_correlatorLogDirectory))
                psi.Environment["TITAN_CORRELATOR_LOG_DIR"] = _correlatorLogDirectory;
            _watcherProcess = Process.Start(psi);
            return (true, "Watcher launch requested. Waiting for readiness...");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to start watcher: {ex.Message}");
        }
    }

    /// <summary>Fresh readiness, not process detection (FORU.TXT 2.4/3.4): requires
    /// watcher_runtime.json to actually exist and be written after requestedAtUtc, not a stale
    /// leftover from a previous run.</summary>
    public bool IsWatcherReady(DateTime requestedAtUtc)
    {
        if (!IsWatcherRunning(out _)) return false;
        if (!File.Exists(WatcherRuntimeFile)) return false;
        try
        {
            if (File.GetLastWriteTimeUtc(WatcherRuntimeFile) < requestedAtUtc) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(WatcherRuntimeFile));
            return doc.RootElement.TryGetProperty("state", out var s) &&
                s.ValueKind == JsonValueKind.String &&
                !string.IsNullOrEmpty(s.GetString());
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return false;
        }
    }

    /// <summary>True unless watcher_runtime.json explicitly says dry_run is off — defaults to
    /// treating an unreadable/missing state as dry-run (the safe assumption) rather than assuming
    /// live response execution.</summary>
    public bool IsDryRun()
    {
        if (!File.Exists(WatcherRuntimeFile)) return true;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(WatcherRuntimeFile));
            return !doc.RootElement.TryGetProperty("dry_run", out var d) || d.ValueKind != JsonValueKind.False;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return true;
        }
    }

    public (bool Ok, string Message) StopWatcher()
    {
        if (!IsWatcherRunning(out var pid)) return (true, "Watcher is not running.");
        if (_watcherProcess is null)
            return (true, "Watcher was not started by this GUI session — leaving it running.");

        // A Windows venv python.exe is a launcher. watcher.main runs in its child
        // base-interpreter process and writes that child PID to watcher.pid. Treat
        // either the tracked launcher or one of its descendants as owned by this
        // controller; comparing only the two PIDs orphaned every GUI-started watcher.
        var launcherPid = _watcherProcess.Id;
        var launcherChildren = ProcessTree.GetChildProcessIds(launcherPid);
        if (pid != launcherPid && !launcherChildren.Contains(pid))
            return (true, "Watcher was not started by this GUI session — leaving it running.");
        try
        {
            using var process = Process.GetProcessById(pid);
            // Found live: a venv's python.exe re-execs into a separate child interpreter process
            // (the one actually running watcher.main) rather than running in-process -- snapshot it
            // now so it can still be cleaned up even when the launcher stub exits gracefully on its
            // own below and Kill(entireProcessTree) is never reached for it.
            var childPids = launcherChildren
                .Concat(ProcessTree.GetChildProcessIds(pid))
                .Append(launcherPid)
                .Where(candidate => candidate != pid)
                .Distinct()
                .ToList();
            // These Python services are created headlessly. In a console-hosted
            // acceptance run they can nevertheless inherit the caller's console;
            // CTRL_C_EVENT would then interrupt PowerShell/testhost as well. Use
            // the verified owned process tree instead of a console-wide signal.
            //
            // Santosh, 2026-08-27: "Stop All is closing the application." entireProcessTree:true
            // here used to also do a *live* tree-walk (anything whose recorded ParentProcessId
            // currently resolves to this PID), which on a machine with heavy process churn can
            // catch an unrelated process -- up to and including this GUI's own -- if a PID it
            // once used got recycled. The childPids snapshot above plus KillSurvivingChildren
            // below already give this the exact same cleanup guarantee deliberately, without that
            // live-walk risk, so the flag was doing nothing but adding danger.
            if (!process.HasExited)
            {
                process.Kill();
                process.WaitForExit(3000);
            }
            KillSurvivingChildren(childPids);
            return (true, "Watcher stopped (owned process tree terminated)." );
        }
        catch (ArgumentException)
        {
            return (true, "Watcher had already exited.");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to stop watcher: {ex.Message}");
        }
        finally
        {
            _watcherProcess?.Dispose();
            _watcherProcess = null;
            try { File.Delete(WatcherPidFile); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private string TokenFilePath => Path.Combine(_customRuleRoot, "data", "secrets", "gekko_api_token.dpapi");

    public async Task<(bool Ok, string Message)> StartApiAsync(CancellationToken ct = default)
    {
        var health = await _apiClient.CheckHealthAsync(ct);
        if (health.Reachable && health.Success) return (true, "API already running and reachable.");

        if (!File.Exists(PythonExePath))
            return (false, $"Python virtual environment not found at {PythonExePath}.");

        try
        {
            // FOUND LIVE (real, previously-unknown bug): launching uvicorn directly here, unlike
            // desktop.py's own _start_api(), never set GEKKO_API_TOKEN on the child process and
            // never published the DPAPI token file CustomRuleApiClient.TryGetToken reads back.
            // app/main.py's local_api_auth middleware fails CLOSED (503 "unauthenticated_launch_
            // refused") on every /api/* route except /api/health when no token is set and
            // GEKKO_ALLOW_UNAUTHENTICATED_LOCAL isn't explicitly opted into -- so every Custom Rule
            // wizard action (parse-rule, watcher-capabilities, evidence, approve, ...) launched this
            // way was silently broken end-to-end, while /api/health alone (which the old "is it
            // running" checks used) kept reporting healthy. Generating and publishing a real
            // per-launch token here, the same way desktop.py does, is the actual fix -- both sides
            // already had the pieces (DpapiUnprotect.TryProtect existed, unused for this).
            var token = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            var psi = new ProcessStartInfo
            {
                FileName = PythonExePath,
                Arguments = "-m uvicorn app.main:app --host 127.0.0.1 --port 8765",
                WorkingDirectory = _customRuleRoot,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["GEKKO_API_TOKEN"] = token;
            PublishToken(token);
            _apiProcess = Process.Start(psi);
            return (true, "API launch requested. Waiting for readiness...");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to start API: {ex.Message}");
        }
    }

    /// <summary>Mirrors desktop.py's _publish_token: best-effort (a failure here means the wizard
    /// will honestly report the API as unreachable/unauthenticated rather than crashing Start All).</summary>
    private void PublishToken(string token)
    {
        try
        {
            var path = TokenFilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var encrypted = DpapiUnprotect.TryProtect(Encoding.UTF8.GetBytes(token));
            if (encrypted is not null) File.WriteAllBytes(path, encrypted);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best effort */ }
    }

    public async Task<bool> IsApiReadyAsync(CancellationToken ct = default)
    {
        var health = await _apiClient.CheckHealthAsync(ct);
        return health.Reachable && health.Success;
    }

    public (bool Ok, string Message) StopApi()
    {
        if (_apiProcess is null) return (true, "API was not started by this GUI session — leaving it running.");
        try
        {
            if (_apiProcess.HasExited) return (true, "API had already exited.");
            // Same orphaning risk as StopWatcher (see its comment): snapshot the launcher's real
            // interpreter child before attempting graceful shutdown.
            var childPids = ProcessTree.GetChildProcessIds(_apiProcess.Id);
            // See StopWatcher: never broadcast Ctrl+C from a headless service
            // shutdown because the Python process can share the invoking console.
            // Also see StopWatcher's 2026-08-27 comment: no entireProcessTree here either, for the
            // same reason -- the childPids snapshot + KillSurvivingChildren below is the real
            // cleanup guarantee; the flag only added a live-tree-walk misfire risk on top.
            if (!_apiProcess.HasExited)
            {
                _apiProcess.Kill();
                _apiProcess.WaitForExit(3000);
            }
            KillSurvivingChildren(childPids);
            return (true, "API stopped (owned process tree terminated)." );
        }
        catch (Exception ex)
        {
            return (false, $"Failed to stop API: {ex.Message}");
        }
        finally
        {
            _apiProcess?.Dispose();
            _apiProcess = null;
            // Mirrors desktop.py's own cleanup: an orphaned token file would otherwise let
            // TryGetToken keep succeeding with a token no process still honors.
            try { File.Delete(TokenFilePath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Best-effort cleanup for the real interpreter child a venv python.exe launcher spawns
    /// (see ProcessTree's doc comment) -- a PID that already exited on its own (the common case, when
    /// the child DID honor Ctrl+C) is not an error.</summary>
    private static void KillSurvivingChildren(List<int> childPids)
    {
        foreach (var childPid in childPids)
        {
            try
            {
                using var child = Process.GetProcessById(childPid);
                if (!child.HasExited)
                {
                    // Santosh, 2026-08-27: found live -- this third entireProcessTree call site
                    // (the other two in this file were already fixed) is exactly the same misfire
                    // risk: killing childPid's own tree by live PID-parent lookup, not just childPid
                    // itself. See StopWatcher's comment above for the full explanation.
                    child.Kill();
                    // StopApi/StopWatcher promise that the owned process tree is terminated.
                    // Waiting here closes the race where the next lifecycle operation could still
                    // observe a dying venv interpreter after Stop had already returned success.
                    child.WaitForExit(3000);
                }
            }
            catch (ArgumentException) { /* already exited */ }
            catch (InvalidOperationException) { /* already exited */ }
        }
    }
}
