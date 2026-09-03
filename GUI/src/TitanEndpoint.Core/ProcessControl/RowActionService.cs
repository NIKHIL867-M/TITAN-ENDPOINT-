using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>
/// Real, per-row response actions available from any endpoint's live event table (Santosh,
/// 2026-08-04 review: "if I click any log I should need to get some option like stop or isolate
/// or open in location"). Deliberately outside any single page's ViewModel so Process/Files/
/// Applications/Port all get the identical, once-reviewed safety behavior rather than four
/// independent re-implementations.
///
/// Every mutating action here is a real OS-level side effect (kills a process, adds a firewall
/// rule) — never simulated. Safety posture mirrors the existing guardrails already established in
/// this codebase (EndpointProcessController.Stop()'s path verification; CUSTOM RULE's
/// action_engine._revalidate_kill_target): revalidate the live target immediately before acting,
/// and refuse outright rather than guess when identity can't be confirmed.
/// </summary>
public static class RowActionService
{
    /// <summary>Never stoppable/isolatable from a log row, regardless of what the row claims —
    /// core OS processes and TITAN's own six native collectors (stopping those must go through
    /// EndpointHeaderViewModel's own start/stop control, which the operator can see and which
    /// updates the endpoint's status badge; a silent kill from a log row would leave the GUI
    /// showing "Active" for a collector that's actually dead).</summary>
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "registry",
        "titan_process.exe", "titan.exe", "application_endpoint.exe", "file_test.exe",
        "usb_test.exe", "correlator.exe",
    };

    public static (bool Ok, string Message) OpenFileLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (false, "This event has no file path to open.");

        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
                return (true, $"Opened Explorer at {path}.");
            }

            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
                return (true, $"The file itself no longer exists; opened its last known folder instead: {dir}");
            }

            return (false, $"Neither the file nor its containing folder exists on disk anymore: {path}");
        }
        catch (Exception ex)
        {
            return (false, $"Could not open Explorer: {ex.Message}");
        }
    }

    /// <summary>Kills the live process by PID, but only after revalidating (immediately before
    /// acting, not from the possibly-stale row data) that the PID still belongs to a process whose
    /// name is consistent with what the row claims — Windows recycles PIDs, so a row captured
    /// minutes ago could now point at an unrelated process. Refuses protected names outright.</summary>
    public static (bool Ok, string Message) StopProcess(int pid, string? expectedName)
    {
        if (pid <= 0)
            return (false, "This event has no process ID to stop.");

        try
        {
            using var p = Process.GetProcessById(pid);
            var liveName = SafeProcessName(p);
            if (liveName is null)
                return (false, $"PID {pid} exited before it could be stopped.");

            if (ProtectedProcessNames.Contains(liveName) || ProtectedProcessNames.Contains(liveName + ".exe"))
                return (false, $"Refusing to stop {liveName} (pid {pid}) — this is a protected system or TITAN component process. Use the endpoint's own Start/Stop control instead.");

            if (!string.IsNullOrWhiteSpace(expectedName))
            {
                var expectedBase = Path.GetFileNameWithoutExtension(expectedName);
                if (!string.Equals(expectedBase, liveName, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"PID {pid} is now running \"{liveName}\", not \"{expectedName}\" — the PID looks like it was reused since this event was captured. Refusing to stop it.");
                }
            }

            p.Kill(entireProcessTree: false);
            p.WaitForExit(3000);
            return (true, $"Stop requested for {liveName} (pid {pid}).");
        }
        catch (ArgumentException)
        {
            return (true, $"Process {pid} had already exited.");
        }
        catch (Win32Exception ex)
        {
            return (false, $"Could not stop pid {pid}: {ex.Message} (this usually means the GUI needs to run as Administrator).");
        }
        catch (Exception ex)
        {
            return (false, $"Could not stop pid {pid}: {ex.Message}");
        }
    }

    private static string? SafeProcessName(Process p)
    {
        try { return p.HasExited ? null : p.ProcessName; }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>Blocks all inbound and outbound network traffic for one executable via a named
    /// Windows Firewall rule pair, scoped by program path (not by PID — PIDs churn, the executable
    /// on disk is the stable identity). Requires the GUI process to already be elevated; this
    /// deliberately does not attempt its own UAC prompt (a surprise elevation dialog from a table
    /// row click would be more disruptive than a clear failure message telling the operator to
    /// restart elevated, matching how this app already asks for elevation up front for Start All).</summary>
    public static (bool Ok, string Message) IsolateProcess(string? exePath, string? displayName)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return (false, "This event has no executable path — Windows Firewall rules are scoped by program path, so isolation needs one.");
        if (!File.Exists(exePath))
            return (false, $"Cannot isolate: {exePath} no longer exists on disk.");

        var name = displayName ?? Path.GetFileName(exePath);
        var ruleName = RuleName(exePath);

        var (okOut, msgOut) = RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=out program=\"{exePath}\" action=block enable=yes");
        if (!okOut) return (false, msgOut);

        var (okIn, msgIn) = RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=in program=\"{exePath}\" action=block enable=yes");
        if (!okIn)
        {
            // Partial isolation (outbound only) is worse than none — clean up before reporting failure.
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
            return (false, msgIn);
        }

        return (true, $"{name} isolated — inbound and outbound network blocked at the firewall for {exePath}.");
    }

    public static (bool Ok, string Message) RemoveIsolation(string? exePath, string? displayName)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return (false, "No executable path available.");

        var name = displayName ?? Path.GetFileName(exePath);
        var (ok, msg) = RunNetsh($"advfirewall firewall delete rule name=\"{RuleName(exePath)}\"");
        return ok ? (true, $"Isolation removed for {name}.") : (false, msg);
    }

    /// <summary>Real check against the live firewall rule set — never cached/assumed, so the GUI
    /// never claims a process is isolated after e.g. someone else removed the rule externally.</summary>
    public static bool IsIsolated(string? exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return false;
        var (ok, output) = RunNetsh($"advfirewall firewall show rule name=\"{RuleName(exePath)}\"");
        return ok && !output.Contains("No rules match", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Deterministic per-path rule identity (must be stable across GUI restarts so
    /// IsIsolated/RemoveIsolation find the exact same rule a prior Isolate call created — a random
    /// or process-lifetime-scoped hash would orphan old rules and never recognize them as
    /// isolated). SHA-256 rather than string.GetHashCode(), which .NET randomizes per process.</summary>
    private static string RuleName(string exePath)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(exePath.ToLowerInvariant()));
        return "TitanEndpoint-Isolate-" + Convert.ToHexString(bytes)[..16];
    }

    private static (bool Ok, string Output) RunNetsh(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return (false, "Could not launch netsh.exe.");

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);

            if (proc.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                return (false, $"netsh failed (exit {proc.ExitCode}): {detail.Trim()} — firewall changes usually require running this GUI as Administrator.");
            }
            return (true, stdout);
        }
        catch (Exception ex)
        {
            return (false, $"Could not run netsh: {ex.Message}");
        }
    }
}
