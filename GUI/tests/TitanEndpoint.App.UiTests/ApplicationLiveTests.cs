using System.Diagnostics;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>Live acceptance for the Application endpoint: verifies the real discovered catalog,
/// starts application_endpoint.exe through the product GUI, generates activity from cmd.exe (a
/// default watched application), and proves the resulting native records reach the Activity grid.</summary>
public static class ApplicationLiveTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        using var profile = new IsolatedTestProfile();
        var gui = profile.LaunchAndWaitForMainWindow();
        using var trafficCts = new CancellationTokenSource();
        Task? traffic = null;
        try
        {
            var navigated = UiAutomationHelpers.SelectByLabel(
                IsolatedTestProfile.GetRootElement(gui), "Applications");
            Report(failures, navigated, "Navigate to Applications page");
            if (!navigated) return failures;
            Thread.Sleep(800);

            var catalogRows = CountRows(gui, "ApplicationCatalogGrid");
            Report(failures, catalogRows > 0,
                $"Catalog: real installed/running applications are listed (found {catalogRows} visible rows)");

            var root = IsolatedTestProfile.GetRootElement(gui);
            var start = UiAutomationHelpers.FindByAutomationId(root, "StartStopEndpointButton");
            Report(failures, start is not null && start.Current.Name.Contains("START ENDPOINT"),
                "Applications: START ENDPOINT button present before start");
            if (start is null) return failures;

            Report(failures, Process.GetProcessesByName("application_endpoint").Length == 0,
                "Applications: application_endpoint.exe is not already running (clean start)");
            UiAutomationHelpers.Invoke(start);
            var started = UiAutomationHelpers.WaitUntil(
                () => Process.GetProcessesByName("application_endpoint").Length == 1,
                TimeSpan.FromSeconds(20));
            Report(failures, started, "Applications: application_endpoint.exe is running after Start");
            if (!started) return failures;

            var activityTab = FindTab(gui, "Activity");
            Report(failures, activityTab is not null, "Activity tab is present and selectable");
            if (activityTab is not null && activityTab.TryGetCurrentPattern(
                    SelectionItemPattern.Pattern, out var selection))
                ((SelectionItemPattern)selection).Select();
            Thread.Sleep(500);

            traffic = GenerateWatchedActivityAsync(trafficCts.Token);
            var gotRows = UiAutomationHelpers.WaitUntil(
                () => CountRows(gui, "ApplicationActivityGrid") > 0,
                TimeSpan.FromSeconds(30));
            Report(failures, gotRows,
                "Activity: real watched-application records appear after cmd.exe activity");

            if (gotRows)
            {
                RunFilterRoundTrip(gui, failures);
            }

            trafficCts.Cancel();
            var stop = UiAutomationHelpers.FindByAutomationId(
                IsolatedTestProfile.GetRootElement(gui), "StartStopEndpointButton");
            if (stop is not null && stop.Current.IsEnabled && stop.Current.Name.Contains("STOP ENDPOINT"))
                UiAutomationHelpers.Invoke(stop);
            var exited = UiAutomationHelpers.WaitUntil(
                () => Process.GetProcessesByName("application_endpoint").Length == 0,
                TimeSpan.FromSeconds(15));
            Report(failures, exited,
                "Applications: application_endpoint.exe exited after Stop without an orphan");
        }
        finally
        {
            trafficCts.Cancel();
            try { traffic?.Wait(TimeSpan.FromSeconds(3)); } catch { }
            IsolatedTestProfile.CloseAndWait(gui);
            foreach (var p in Process.GetProcessesByName("application_endpoint"))
                try { p.Kill(); } catch { }
        }
        return failures;
    }

    private static Task GenerateWatchedActivityAsync(CancellationToken ct) => Task.Run(() =>
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var child = Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    // Hold the watched process across multiple native collection intervals. A
                    // two-packet ping can disappear before the real endpoint observes it.
                    Arguments = "/c ping -t 127.0.0.1",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                if (child is not null)
                {
                    ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(5));
                    if (!child.HasExited) child.Kill(entireProcessTree: true);
                    child.WaitForExit(3000);
                }
            }
            catch { }
            ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(1));
        }
    }, ct);

    private static void RunFilterRoundTrip(Process gui, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(gui);
        var filter = UiAutomationHelpers.FindByAutomationId(root, "ApplicationActivityFilterTextBox");
        if (filter is null || !filter.TryGetCurrentPattern(ValuePattern.Pattern, out var valueObject))
        {
            Report(failures, false, "Activity filter supports text entry");
            return;
        }
        var value = (ValuePattern)valueObject;
        value.SetValue("titan-no-match-" + Guid.NewGuid().ToString("N")[..8]);
        Thread.Sleep(400);
        Report(failures, CountRows(gui, "ApplicationActivityGrid") == 0,
            "Activity filter: unmatched text empties the real view");
        value.SetValue("cmd");
        var foundCmd = UiAutomationHelpers.WaitUntil(
            () => CountRows(gui, "ApplicationActivityGrid") > 0,
            TimeSpan.FromSeconds(12));
        Report(failures, foundCmd && CountRows(gui, "ApplicationActivityGrid") > 0,
            "Activity filter: cmd finds the generated watched-application rows");
        value.SetValue("");
        Thread.Sleep(400);
        Report(failures, CountRows(gui, "ApplicationActivityGrid") > 0,
            "Activity filter: clearing restores the real view");
    }

    private static AutomationElement? FindTab(Process gui, string name)
    {
        var condition = new AndCondition(
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.TabItem),
            new PropertyCondition(AutomationElement.NameProperty, name));
        return IsolatedTestProfile.GetRootElement(gui).FindFirst(TreeScope.Descendants, condition);
    }

    private static int CountRows(Process gui, string automationId)
    {
        var grid = UiAutomationHelpers.FindByAutomationId(
            IsolatedTestProfile.GetRootElement(gui), automationId);
        return grid?.FindAll(TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem)).Count ?? 0;
    }

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}
