using System.ComponentModel;
using System.Diagnostics;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Diagnostics;
using TitanEndpoint.Core.Manifest;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>
/// Truthful start/stop/detect for one of the six native collectors. Detection is by live OS
/// process lookup, verified against the configured executable's absolute path (FORU.TXT section
/// 2: "A matching process name alone is not sufficient") — never inferred from log activity, and
/// never adopted as "ours" just because the process name matches. See ProcessImagePath for why
/// this works even when the GUI itself isn't elevated but the collector is.
/// </summary>
public sealed class EndpointProcessController
{
    private readonly EndpointDefinition _definition;
    private readonly Mutex _startGate;

    /// <summary>FORU.TXT 0.3: "must not open Command Prompt, PowerShell, or separate console
    /// windows... redirect stdout/stderr to a bounded per-endpoint Diagnostics panel." Optional
    /// (null is a legal, honest degraded mode — e.g. regression tests construct a controller with
    /// no UI to report to) — set by EndpointRuntimeState so every launch this controller performs
    /// feeds the same panel.</summary>
    public EndpointDiagnostics? Diagnostics { get; set; }

    /// <summary>Set by Start() when it took the non-elevated, redirected-stdio launch branch (see
    /// Start()'s comment on why that branch cannot give the child its own attachable console).
    /// Stop() uses this to skip the doomed-to-fail ConsoleCtrlSender attempt for exactly that
    /// process instance -- null (unknown) for a process this controller didn't itself launch (e.g.
    /// detected already running from a previous session), where the safe default is to still try.</summary>
    private bool? _lastLaunchUsedRedirectedStdio;

    public EndpointProcessController(EndpointDefinition definition)
    {
        _definition = definition;
        // Cross-process guard against two Start() calls racing to launch the same component
        // twice — two GUI instances, or rapid repeated button presses (FORU.TXT section 2.4 /
        // section 3's "repeated rapid button presses" acceptance-gate item). "Local\" scope
        // (current session) rather than "Global\" since this doesn't need to coordinate across
        // Windows sessions/users, only within this desktop session.
        _startGate = new Mutex(false, $@"Local\TitanEndpoint_StartGate_{definition.Id}");
    }

    public RunningProcessInfo? DetectRunning()
    {
        if (string.IsNullOrEmpty(_definition.ExeBaseName)) return null;

        var configuredPath = _definition.ResolveExePath();
        var procs = Process.GetProcessesByName(_definition.ExeBaseName);
        if (procs.Length == 0) return null;

        try
        {
            RunningProcessInfo? unverifiedFallback = null;

            foreach (var p in procs)
            {
                var path = TryGetPath(p);
                DateTime startUtc;
                try { startUtc = p.StartTime.ToUniversalTime(); }
                catch { startUtc = DateTime.UtcNow; }

                if (path is not null)
                {
                    var matches = !string.IsNullOrEmpty(configuredPath) &&
                        string.Equals(NormalizePath(path), NormalizePath(configuredPath), StringComparison.OrdinalIgnoreCase);
                    if (matches)
                    {
                        return new RunningProcessInfo
                        {
                            Pid = p.Id,
                            StartTimeUtc = startUtc,
                            ExecutablePath = path,
                            PathVerified = true
                        };
                    }
                    // Same process name, different executable path — e.g. a stale build launched
                    // manually from another folder. Explicitly not "ours"; keep scanning other
                    // same-named processes rather than adopting this one.
                    continue;
                }

                // Path unreadable for this candidate (should be rare — see ProcessImagePath).
                // Remember it only as a last-resort degraded fallback if nothing else matches.
                unverifiedFallback ??= new RunningProcessInfo
                {
                    Pid = p.Id,
                    StartTimeUtc = startUtc,
                    ExecutablePath = null,
                    PathVerified = false
                };
            }

            return unverifiedFallback;
        }
        finally
        {
            foreach (var p in procs) p.Dispose();
        }
    }

    private static string? TryGetPath(Process p)
    {
        try { return p.MainModule?.FileName; }
        catch (Win32Exception)
        {
            // Almost certainly a higher-integrity (elevated) process than this one — fall back to
            // the limited-info API, which Windows permits across integrity levels for the same user.
            return ProcessImagePath.TryGetImagePath(p.Id);
        }
        catch (InvalidOperationException)
        {
            return null; // exited between GetProcessesByName and here
        }
    }

    private static string NormalizePath(string path) => Path.GetFullPath(path).TrimEnd('\\');

    public (bool Ok, string Message) Start()
    {
        if (string.IsNullOrEmpty(_definition.ExeBaseName))
            return (false, $"{_definition.DisplayName} is not started as a standalone process from here.");

        if (!_startGate.WaitOne(TimeSpan.Zero))
            return (false, $"A start for {_definition.DisplayName} is already in progress.");

        try
        {
            if (DetectRunning() is not null)
                return (false, $"{_definition.DisplayName} is already running.");

            var exePath = _definition.ResolveExePath();
            if (!File.Exists(exePath))
                return (false, $"Executable not found at {exePath}. Check the path in Settings.");

            // FORU.TXT section 1: "Fail startup with a clear error if an executable... is
            // missing" / "reject missing, mismatched or stale builds." NotConfigured (no
            // manifest entry for this component) is allowed through — it means no manifest is
            // configured yet, not that this specific build was rejected.
            var manifestState = _definition.ValidateAgainstManifest();
            if (manifestState == ManifestValidationState.HashMismatch)
                return (false, $"{_definition.DisplayName}'s executable at {exePath} does not match the SHA-256 recorded in runtime-manifest.json. Refusing to start an unverified build — regenerate the manifest if this build is intentional.");
            if (manifestState == ManifestValidationState.FileMissing)
                return (false, $"{_definition.DisplayName}'s manifest-configured executable was not found at {exePath}.");

            // FORU.TXT 0.3: "must not open Command Prompt, PowerShell, or separate console
            // windows... launch verified native children with no visible console window and
            // preserve exact PID/path ownership." UseShellExecute=true (the only way to trigger a
            // "runas" UAC elevation) is unavoidable when this GUI process itself is not already
            // elevated and the target needs to be -- but WindowStyle=Hidden still suppresses the
            // console window Windows would otherwise show for that elevated console-subsystem
            // child (a well-established ShellExecuteEx SW_HIDE behavior). When this GUI is
            // already elevated (the normal "restart as Administrator, then Start All" workflow),
            // or the target needs no elevation at all (Correlator), no UAC/ShellExecute is needed
            // at all: launch directly with CreateNoWindow + redirected stdio, which additionally
            // makes real Diagnostics-panel capture possible -- something ShellExecute fundamentally
            // cannot support regardless of window visibility.
            var needsShellElevate = _definition.RequiresElevation && !ElevationHelper.IsCurrentProcessElevated();

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                WorkingDirectory = _definition.ResolveWorkingDirectory(),
                Arguments = _definition.ResolveCommandArguments(),
            };

            if (needsShellElevate)
            {
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Diagnostics?.AppendSystem("Launching via UAC elevation (runas) -- stdout/stderr capture is not " +
                    "available for this launch path; only a hidden window is guaranteed, not redirected diagnostics.");
            }
            else
            {
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
            }

            try
            {
                var started = Process.Start(psi);
                if (started is null)
                    return (false, $"Failed to start {_definition.DisplayName}: Process.Start returned null.");

                _lastLaunchUsedRedirectedStdio = !needsShellElevate;
                if (!needsShellElevate)
                {
                    var diagnostics = Diagnostics;
                    if (diagnostics is not null)
                    {
                        started.OutputDataReceived += (_, e) => { if (e.Data is not null) diagnostics.Append(DiagnosticLevel.Info, e.Data); };
                        started.ErrorDataReceived += (_, e) => { if (e.Data is not null) diagnostics.Append(DiagnosticLevel.Error, e.Data); };
                        started.BeginOutputReadLine();
                        started.BeginErrorReadLine();
                    }
                    // Deliberately NOT disposed here (unlike the elevated path) -- disposing would
                    // detach the redirected-output event handlers and stop diagnostics capture.
                    // The OS process itself is untouched either way; this only affects whether this
                    // .NET Process handle object keeps forwarding its output events.
                }
                else
                {
                    started.Dispose();
                }
                return (true, $"Launch requested for {_definition.DisplayName}. Waiting for heartbeat...");
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return (false, "Elevation prompt was cancelled.");
            }
            catch (Exception ex)
            {
                return (false, $"Failed to start {_definition.DisplayName}: {ex.Message}");
            }
        }
        finally
        {
            _startGate.ReleaseMutex();
        }
    }

    public (bool Ok, string Message) Stop(TimeSpan? gracefulTimeout = null)
    {
        var running = DetectRunning();
        if (running is null)
            return (false, $"{_definition.DisplayName} is not running.");

        if (!running.PathVerified)
        {
            // Found a same-named process but couldn't confirm its path matches the configured
            // executable — refuse rather than risk terminating something unrelated (FORU.TXT
            // section 2.3: never force-kill a same-named process whose path isn't confirmed).
            return (false, $"Found a process named {_definition.ExeBaseName} but could not verify its executable path. Refusing to stop it — check Endpoint Details.");
        }

        gracefulTimeout ??= TimeSpan.FromSeconds(5);

        try
        {
            using var process = Process.GetProcessById(running.Pid);

            // Santosh, 2026-08-27: "when I clicked Stop All it closed the application too" --
            // reproduced live and traced to exactly this: ConsoleCtrlSender.TrySendCtrlC attaches
            // OUR process to the target's console (AttachConsole) and calls GenerateConsoleCtrlEvent,
            // which signals every process on that console, including the caller. Its own internal
            // guards (skip if consoles overlap, SetConsoleCtrlHandler(null, true) to self-ignore)
            // were not enough to stop it from taking this GUI process down for an elevated endpoint
            // (Port/USB, launched via a UAC shell-elevate path, so _lastLaunchUsedRedirectedStdio is
            // false and this branch used to run). Already known unreliable for the *target* since
            // 2026-08-02; now confirmed unsafe for the *caller* too. Removed entirely -- go straight
            // to the forced Kill() below, which every endpoint already falls back to anyway.
            if (!process.HasExited)
            {
                // Santosh, 2026-08-27: "when I clicked on Stop All it is closing the application
                // also." entireProcessTree:true walks the live process snapshot for anything whose
                // recorded ParentProcessId matches this PID and kills those too -- .NET does that
                // walk without checking process creation time, so on a machine with heavy process
                // churn (this one: hundreds of short-lived build/PowerShell processes per session)
                // a since-reused PID can make an unrelated process, up to and including this GUI's
                // own process, look like a "descendant" of the collector being stopped. None of
                // these five native collectors are known to spawn child processes of their own, so
                // there is nothing legitimate for the tree variant to actually clean up here --
                // only killing the collector's own single process removes that misfire risk.
                process.Kill();
                process.WaitForExit(3000);
                // FORU.TXT 0.2: "force-kill are last-resort recovery, must be labelled Forced."
                Diagnostics?.Append(DiagnosticLevel.Warning, $"{_definition.DisplayName}: force-terminated on Stop.");
                return (true, $"[FORCED] {_definition.DisplayName} was force-terminated.");
            }
            return (true, $"{_definition.DisplayName} exited on its own before the forced-kill step ran.");
        }
        catch (ArgumentException)
        {
            return (true, $"{_definition.DisplayName} had already exited.");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to stop {_definition.DisplayName}: {ex.Message}");
        }
    }
}
