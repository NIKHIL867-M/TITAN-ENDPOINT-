using System.Diagnostics;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>One-off, manually-invoked demo runner -- NOT part of the automated regression gate (it
/// deliberately leaves the GUI window open at the end instead of cleaning up, so the operator can
/// look at real correlated data directly on screen). Launches the real GUI against real production
/// settings (not an isolated test profile), starts all six native endpoints, generates real
/// cross-endpoint correlatable activity for a few minutes, stops the fleet cleanly, then positions
/// the GUI on the Correlation page with a real group selected and the Raw JSON tab open so the
/// operator can inspect the actual merged session_timeline record themselves.</summary>
public static class FleetDemo
{
    private static readonly (string NavLabel, string ProcessBaseName)[] Fleet =
    {
        ("Process", "titan_process"),
        ("Network", "titan"),
        ("Applications", "application_endpoint"),
        ("Files", "file_test"),
        ("Port / USB", "usb_test"),
        ("Correlation", "correlator"),
    };

    public static void Run(int runSeconds)
    {
        Console.WriteLine($"[DEMO] Launching the real GUI (production settings) and starting all six endpoints for {runSeconds}s of real activity...");
        var psi = new ProcessStartInfo { FileName = IsolatedTestProfile.FindAppExecutable(), UseShellExecute = false };
        var process = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null.");
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(25);
        while (process.MainWindowHandle == IntPtr.Zero && DateTime.UtcNow < deadline) { Thread.Sleep(200); process.Refresh(); }
        if (process.MainWindowHandle == IntPtr.Zero) throw new TimeoutException("GUI did not present a main window.");
        Thread.Sleep(2500);

        var started = new List<string>();
        foreach (var (navLabel, processBaseName) in Fleet)
        {
            if (StartOne(process, navLabel, processBaseName)) started.Add(processBaseName);
        }
        Console.WriteLine($"[DEMO] Started: {string.Join(", ", started)}");

        using var trafficCts = new CancellationTokenSource();
        var trafficTask = GenerateCrossEndpointActivityAsync(trafficCts.Token);

        Console.WriteLine($"[DEMO] Letting the fleet run for {runSeconds}s with real curl.exe/cmd.exe/ping.exe/file activity so the correlator has genuine cross-endpoint evidence...");
        var waited = 0;
        while (waited < runSeconds)
        {
            Thread.Sleep(Math.Min(15000, (runSeconds - waited) * 1000));
            waited += 15;
            Console.WriteLine($"[DEMO] ...{Math.Min(waited, runSeconds)}s elapsed");
        }
        trafficCts.Cancel();
        try { trafficTask.Wait(TimeSpan.FromSeconds(5)); } catch { /* best effort */ }

        Console.WriteLine("[DEMO] Stopping Process/Network/Applications/Files/Port/USB (Correlator stays running so its own window can be inspected live)...");
        foreach (var (navLabel, processBaseName) in Fleet)
        {
            if (processBaseName == "correlator") continue;
            StopOne(process, navLabel, processBaseName);
        }

        Console.WriteLine("[DEMO] Navigating to Correlation and selecting the best-covered real group...");
        NavigateTo(process, "Correlation");
        Thread.Sleep(1000);

        var root = AutomationElement.FromHandle(process.MainWindowHandle);
        var gotGroups = UiAutomationHelpers.WaitUntil(
            () => CountDescendants(AutomationElement.FromHandle(process.MainWindowHandle), "CorrelationGroupsGrid", ControlType.DataItem) > 0,
            TimeSpan.FromSeconds(20));
        if (!gotGroups)
        {
            Console.WriteLine("[DEMO] No correlated group appeared -- leaving the GUI open on the Correlation page as-is for manual inspection.");
            return;
        }

        var grid = UiAutomationHelpers.FindByAutomationId(AutomationElement.FromHandle(process.MainWindowHandle), "CorrelationGroupsGrid");
        var rows = grid!.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem));
        AutomationElement? best = null;
        var bestMemberCount = -1;
        foreach (AutomationElement row in rows)
        {
            var texts = row.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text));
            foreach (AutomationElement t in texts)
            {
                if (int.TryParse(t.Current.Name, out var n) && n > bestMemberCount) { bestMemberCount = n; best = row; }
            }
        }
        best ??= rows.Count > 0 ? (AutomationElement)rows[rows.Count - 1] : null;
        if (best is not null && best.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var selPatternObj))
        {
            ((SelectionItemPattern)selPatternObj).Select();
            Console.WriteLine($"[DEMO] Selected the group with the most members (approx {bestMemberCount} members).");
        }
        Thread.Sleep(500);

        var switchedToRawJson = SelectTabByHeader(AutomationElement.FromHandle(process.MainWindowHandle), "Raw JSON");
        Console.WriteLine(switchedToRawJson
            ? "[DEMO] Raw JSON tab is now open on the Correlation page -- the real, merged session_timeline record is visible on screen now."
            : "[DEMO] Could not switch to the Raw JSON tab automatically -- click it manually on the Correlation page.");

        try { NativeMethods.SetForegroundWindow(process.MainWindowHandle); } catch { /* best effort */ }
        Console.WriteLine("[DEMO] Done. The GUI window is intentionally left open for inspection -- this demo does not close it.");
    }

    private static bool StartOne(Process process, string navLabel, string processBaseName)
    {
        if (!NavigateTo(process, navLabel)) { Console.WriteLine($"[DEMO] Could not navigate to {navLabel}."); return false; }
        Thread.Sleep(500);
        var btn = UiAutomationHelpers.FindByAutomationId(AutomationElement.FromHandle(process.MainWindowHandle), "StartStopEndpointButton");
        if (btn is null || !btn.Current.Name.Contains("START ENDPOINT")) return Process.GetProcessesByName(processBaseName).Length > 0;
        UiAutomationHelpers.Invoke(btn);
        var started = UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName(processBaseName).Length > 0, TimeSpan.FromSeconds(20));
        if (!started) Console.WriteLine($"[DEMO] {navLabel}: {processBaseName}.exe did not start within 20s.");
        return started;
    }

    private static void StopOne(Process process, string navLabel, string processBaseName)
    {
        if (Process.GetProcessesByName(processBaseName).Length == 0) return;
        if (!NavigateTo(process, navLabel)) return;
        Thread.Sleep(400);
        var btn = UiAutomationHelpers.FindByAutomationId(AutomationElement.FromHandle(process.MainWindowHandle), "StartStopEndpointButton");
        if (btn is null || !btn.Current.IsEnabled || !btn.Current.Name.Contains("STOP ENDPOINT")) return;
        UiAutomationHelpers.Invoke(btn);
        UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName(processBaseName).Length == 0, TimeSpan.FromSeconds(15));
    }

    private static bool NavigateTo(Process process, string navLabel)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try { if (UiAutomationHelpers.SelectByLabel(AutomationElement.FromHandle(process.MainWindowHandle), navLabel)) return true; }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        return false;
    }

    private static Task GenerateCrossEndpointActivityAsync(CancellationToken ct) => Task.Run(() =>
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var i = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var curl = Process.Start(new ProcessStartInfo { FileName = "curl.exe", Arguments = "-s -m 5 https://example.com/", UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                curl?.WaitForExit(6000);
            }
            catch { /* best effort */ }
            try
            {
                using var ping = Process.Start(new ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c ping -n 2 127.0.0.1", UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                ping?.WaitForExit(6000);
            }
            catch { /* best effort */ }
            try
            {
                var path = System.IO.Path.Combine(desktop, $"titan-demo-{i++}.txt");
                System.IO.File.WriteAllText(path, "titan fleet demo activity\n");
                Thread.Sleep(200);
                System.IO.File.Delete(path);
            }
            catch { /* best effort */ }
            Thread.Sleep(2500);
        }
    }, ct);

    private static bool SelectTabByHeader(AutomationElement root, string headerText)
    {
        var cond = new AndCondition(
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.TabItem),
            new PropertyCondition(AutomationElement.NameProperty, headerText));
        var tab = root.FindFirst(TreeScope.Descendants, cond);
        if (tab is null || !tab.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var patternObj)) return false;
        ((SelectionItemPattern)patternObj).Select();
        return true;
    }

    private static int CountDescendants(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return -1;
        return container.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType)).Count;
    }

}
