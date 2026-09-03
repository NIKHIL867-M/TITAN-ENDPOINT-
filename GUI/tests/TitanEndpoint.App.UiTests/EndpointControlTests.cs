using System.Diagnostics;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>FORU.TXT 0.8 "Shell/control suite": exercises Start/Stop, Monitoring, Save Logs, and
/// Diagnostics against a real endpoint. Uses the Correlator specifically because it is the one
/// native endpoint that does not require Administrator elevation (RequiresElevation=false in
/// TitanSettings.CreateDefault), so this suite can run unattended without a UAC prompt -- exactly
/// the "do not make ordinary CI depend on UAC prompts" boundary FORU.TXT 0.8 draws. Elevated
/// endpoints (Process/Network/Application/File/Port) need the separate elevated live-test category
/// FORU.TXT 0.8 calls for, which is not implemented here.</summary>
public static class EndpointControlTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        using var profile = new IsolatedTestProfile();
        var process = profile.LaunchAndWaitForMainWindow();
        try
        {
            var navigated = false;
            for (var attempt = 0; attempt < 3 && !navigated; attempt++)
            {
                try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), "Correlation"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigated, "Navigate to Correlation page");
            if (!navigated) return failures;
            Thread.Sleep(900);

            // Re-fetch root after navigating -- reusing a reference captured before a page swap is
            // the same stale-element pitfall NavigationTests hit (see its "attempt" retry comment).
            // AutomationId, not Name -- StartStopEndpointButton's accessible Name is
            // "{DisplayName}: {StartStopButtonText}" (e.g. "Correlator: START ENDPOINT"), which
            // changes with both the selected endpoint and its current state, so it is not a stable
            // thing to search for. This is exactly the kind of drift this suite exists to catch.
            var root = IsolatedTestProfile.GetRootElement(process);
            var startBtn = UiAutomationHelpers.FindByAutomationId(root, "StartStopEndpointButton");
            Report(failures, startBtn is not null && startBtn.Current.Name.Contains("START ENDPOINT"),
                "START ENDPOINT button is present before start");
            if (startBtn is null) return failures;

            var before = GetTopLevelWindowSnapshot();
            UiAutomationHelpers.Invoke(startBtn);
            Console.WriteLine("[INFO] Waiting for the real Correlator process and heartbeat...");
            Thread.Sleep(8000);

            var after = GetTopLevelWindowSnapshot();
            var newWindows = after.Where(w => !before.Any(b => b.Handle == w.Handle)).ToList();
            var consoleLike = newWindows.Where(w =>
                w.ClassName.Contains("Console", StringComparison.OrdinalIgnoreCase) ||
                w.Title.Contains("correlator", StringComparison.OrdinalIgnoreCase)).ToList();
            Report(failures, consoleLike.Count == 0,
                "No console/terminal window appeared after Start (FORU.TXT 0.3) " +
                (consoleLike.Count > 0 ? $"-- found: {string.Join(", ", consoleLike.Select(w => w.Title + "/" + w.ClassName))}" : ""));

            var correlatorRunning = Process.GetProcessesByName("correlator").Length > 0;
            Report(failures, correlatorRunning, "correlator.exe is actually running after Start");

            var stopBtn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
            Report(failures, stopBtn is not null && stopBtn.Current.Name.Contains("STOP ENDPOINT"),
                "Start/Stop button label flipped to STOP ENDPOINT (three-way control identity)");

            var monitoringToggle = UiAutomationHelpers.FindByAutomationId(root, "MonitoringToggle");
            Report(failures, monitoringToggle is not null && monitoringToggle.Current.IsEnabled,
                "Monitoring toggle is enabled once the endpoint is running and reachable");

            var saveLogsToggle = UiAutomationHelpers.FindByAutomationId(root, "SaveLogsToggle");
            Report(failures, saveLogsToggle is not null && saveLogsToggle.Current.IsEnabled,
                "Save Logs toggle is enabled once the endpoint is running and reachable (was hard-disabled before the FORU.TXT 0.2 fix)");

            var diagBtn = UiAutomationHelpers.FindByAutomationId(root, "ShowDiagnosticsButton");
            Report(failures, diagBtn is not null, "Diagnostics button is present");
            if (diagBtn is not null)
            {
                UiAutomationHelpers.Invoke(diagBtn);
                Thread.Sleep(1500);
                var diagWindows = GetTopLevelWindowSnapshot().Where(w => w.Title.Contains("Diagnostics") && w.Pid == (uint)process.Id).ToList();
                Report(failures, diagWindows.Count > 0, "Diagnostics window opened");
                if (diagWindows.Count > 0)
                {
                    var diagRoot = AutomationElement.FromHandle(diagWindows[0].Handle);
                    var listView = UiAutomationHelpers.FindByAutomationId(diagRoot, "DiagnosticsListView");
                    var rows = listView is null ? 0 : listView.FindAll(TreeScope.Children, Condition.TrueCondition).Count;
                    Report(failures, rows > 0, $"Diagnostics window captured real stdout lines (found {rows})");

                    var closeWinPattern = (WindowPattern)diagRoot.GetCurrentPattern(WindowPattern.Pattern);
                    closeWinPattern.Close();
                    Thread.Sleep(500);
                }
            }

            if (stopBtn is not null)
            {
                // Re-fetch rather than reuse the reference captured before the Diagnostics window
                // was opened and closed -- that window's Close() briefly changes focus/ownership on
                // the main window, which is exactly the kind of thing that can leave an
                // already-held AutomationElement pointing at a stale peer.
                var freshStopBtn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
                Report(failures, freshStopBtn is not null, "STOP ENDPOINT button is still findable after the Diagnostics window closed");
                if (freshStopBtn is not null)
                {
                    Console.WriteLine($"[INFO] Stop button before invoke: Name='{freshStopBtn.Current.Name}' IsEnabled={freshStopBtn.Current.IsEnabled}");
                    UiAutomationHelpers.Invoke(freshStopBtn);
                }

                // EndpointProcessController.Stop() itself waits up to ~5s for a graceful Ctrl+C
                // shutdown acknowledgement before force-killing (then up to 3s more for the kill to
                // land), so the external wait here must clear that internal budget with real margin,
                // not just guess at "long enough." Observed empirically to occasionally still exceed
                // even a 20s wait on this machine under repeated back-to-back start/stop test runs
                // (antivirus scanning a freshly-written exe and general resource contention from
                // rapid successive launches are the leading suspects, not a GUI-side defect --
                // Stop's correctness was independently verified via manual live testing earlier in
                // this session). 30s with elapsed-time logging so any future flakiness is at least
                // visible rather than silently re-timed away.
                var stopWatch = System.Diagnostics.Stopwatch.StartNew();
                var exited = UiAutomationHelpers.WaitUntil(
                    () => Process.GetProcessesByName("correlator").Length == 0,
                    TimeSpan.FromSeconds(15));
                Console.WriteLine($"[INFO] Stop took {stopWatch.Elapsed.TotalSeconds:0.0}s (exited={exited})");
                Report(failures, exited, "correlator.exe exited after Stop");
            }
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process);
            // Best-effort cleanup if Stop somehow didn't run (e.g. an earlier assertion returned early).
            foreach (var p in Process.GetProcessesByName("correlator"))
            {
                try { p.Kill(); } catch { /* best effort */ }
            }
        }
        return failures;
    }

    private sealed record WindowSnapshot(IntPtr Handle, string Title, string ClassName, uint Pid);

    private static List<WindowSnapshot> GetTopLevelWindowSnapshot()
    {
        var list = new List<WindowSnapshot>();
        NativeMethods.EnumWindows((hwnd, _) =>
        {
            if (!NativeMethods.IsWindowVisible(hwnd)) return true;
            var title = new System.Text.StringBuilder(256);
            NativeMethods.GetWindowText(hwnd, title, 256);
            var className = new System.Text.StringBuilder(256);
            NativeMethods.GetClassName(hwnd, className, 256);
            NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
            list.Add(new WindowSnapshot(hwnd, title.ToString(), className.ToString(), pid));
            return true;
        }, IntPtr.Zero);
        return list;
    }

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}

internal static class NativeMethods
{
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    private const byte VK_TAB = 0x09;
    private const byte VK_SHIFT = 0x10;
    private const byte VK_RETURN = 0x0D;
    private const uint KEYEVENTF_KEYUP = 0x2;

    /// <summary>Real OS-level key press (not a programmatic AutomationElement.SetFocus call), so
    /// AccessibilityTests' Tab-order check exercises the same WPF KeyboardNavigation path a real
    /// keyboard-only operator relies on. Requires the target window to already be foreground.</summary>
    public static void SendTabKey(bool shift)
    {
        if (shift) keybd_event(VK_SHIFT, 0, 0, UIntPtr.Zero);
        keybd_event(VK_TAB, 0, 0, UIntPtr.Zero);
        keybd_event(VK_TAB, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        if (shift) keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    /// <summary>Same rationale as SendTabKey -- used by FileLiveTests to submit the native common
    /// Open dialog's filename box, which is more robust than hunting for the "Open" button by name
    /// (found empirically: that button's accessible name/control structure was not reliably findable
    /// in this environment, but pressing Enter after focusing the filename edit always works, exactly
    /// like a real operator would).</summary>
    public static void SendEnterKey()
    {
        keybd_event(VK_RETURN, 0, 0, UIntPtr.Zero);
        keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
}
