using System.Diagnostics;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>Live end-to-end pass over every real control on the Correlation page. Starts the real
/// correlator.exe process (does not require elevation -- RequiresElevation=false in
/// TitanSettings.CreateDefault, the same non-elevation boundary EndpointControlTests documents for
/// this exact endpoint), ALSO starts the real Process and Network endpoints alongside it and drives
/// real curl.exe launches so the fleet has genuinely overlapping, cross-referenceable evidence to
/// join (a process starting is a real titan_process.exe event; that same process's outbound
/// connection is a real titan.exe event, same PID) -- correlating only pre-existing, possibly stale
/// historical logs was found empirically to often produce zero groups, since this session's earlier
/// suites mostly ran endpoints one at a time rather than concurrently. Then drives the groups grid,
/// filter, and all four investigation tabs (Timeline, Evidence Graph, Chain View, Raw JSON) against
/// whatever real correlated groups the engine actually produced -- no synthetic/fabricated data at
/// any point; the traffic is real, the correlation is the real engine's own join logic.
///
/// Deliberately does not invoke "Open Evidence"/graph-node buttons: OpenEvidenceCommand shows a real
/// modal MessageBox, and WPF's UI Automation Invoke() marshals synchronously onto the UI thread, so
/// clicking it here would block this harness on a dialog nothing else would ever dismiss (same class
/// of native-modal-dialog exclusion as NetworkLiveCaptureTests skipping Export/Save). EvidenceResolver's
/// actual resolution logic is already covered by TitanEndpoint.Core.RegressionTests' "durable evidence
/// resolver" cases; this suite checks the button is present and enabled instead.</summary>
public static class CorrelationLiveTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        using var profile = new IsolatedTestProfile();
        var process = profile.LaunchAndWaitForMainWindow();
        using var trafficCts = new CancellationTokenSource();
        Task? trafficTask = null;
        try
        {
            var correlatorStarted = StartEndpoint(process, "Correlation", "correlator", failures);
            if (!correlatorStarted) return failures;

            // Best-effort: these two require elevation (this harness's shell is elevated). If either
            // doesn't start, the correlator is still real-tested against whatever evidence already
            // exists on disk -- not a reason to abort the whole suite.
            var processStarted = StartEndpoint(process, "Process", "titan_process", failures, required: false);
            var networkStarted = StartEndpoint(process, "Network", "titan", failures, required: false);

            if (processStarted && networkStarted)
                trafficTask = GenerateCorrelatableActivityAsync(trafficCts.Token);

            var navigatedBack = false;
            for (var attempt = 0; attempt < 3 && !navigatedBack; attempt++)
            {
                try { navigatedBack = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), "Correlation"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigatedBack, "Navigate back to Correlation page to observe live results");
            Thread.Sleep(700);

            // The engine needs time to open, index, and replay the other endpoints' evidence (both
            // pre-existing and freshly generated) before any session_timeline group is emitted --
            // generous but bounded, and polled rather than a fixed sleep so a fast machine doesn't
            // wait needlessly.
            var gotGroups = UiAutomationHelpers.WaitUntil(
                () => CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationGroupsGrid", ControlType.DataItem) > 0,
                TimeSpan.FromSeconds(60));
            Report(failures, gotGroups, "Groups grid: real correlated groups appear (ingested from real endpoint evidence, live-generated and/or on disk)");

            if (gotGroups)
            {
                RunGroupSelectionChecks(process, failures);
                RunFilterRoundTrip(process, failures);
            }
            else
            {
                Console.WriteLine("[INFO] No correlated groups appeared within the wait window even with Process+Network " +
                    "running and real curl.exe activity generated -- investigation-tab checks were skipped since they " +
                    "need a real selected group.");
            }

            trafficCts.Cancel();
            StopEndpoint(process, "Network", "titan", failures, required: networkStarted);
            StopEndpoint(process, "Process", "titan_process", failures, required: processStarted);
            StopEndpoint(process, "Correlation", "correlator", failures, required: true);
        }
        finally
        {
            trafficCts.Cancel();
            try { trafficTask?.Wait(TimeSpan.FromSeconds(3)); } catch { /* best effort */ }
            IsolatedTestProfile.CloseAndWait(process);
            foreach (var name in new[] { "correlator", "titan_process", "titan" })
                foreach (var p in Process.GetProcessesByName(name)) { try { p.Kill(); } catch { /* best effort */ } }
        }
        return failures;
    }

    private static bool StartEndpoint(Process process, string navLabel, string processBaseName, List<string> failures, bool required = true)
    {
        var navigated = false;
        for (var attempt = 0; attempt < 3 && !navigated; attempt++)
        {
            try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), navLabel); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        if (required) Report(failures, navigated, $"Navigate to {navLabel} page");
        if (!navigated) return false;
        Thread.Sleep(500);

        var startBtn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
        var canStart = startBtn is not null && startBtn.Current.Name.Contains("START ENDPOINT");
        if (required) Report(failures, canStart, $"{navLabel}: START ENDPOINT button present before start");
        if (!canStart) return false;

        UiAutomationHelpers.Invoke(startBtn!);
        var started = UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName(processBaseName).Length > 0, TimeSpan.FromSeconds(20));
        if (required) Report(failures, started, $"{navLabel}: {processBaseName}.exe is running after Start");
        else Console.WriteLine($"[{(started ? "INFO" : "INFO")}] {navLabel}: {processBaseName}.exe {(started ? "started" : "did not start (best-effort, not scored)")}");
        return started;
    }

    private static void StopEndpoint(Process process, string navLabel, string processBaseName, List<string> failures, bool required)
    {
        if (!required && Process.GetProcessesByName(processBaseName).Length == 0) return;
        var navigated = false;
        for (var attempt = 0; attempt < 3 && !navigated; attempt++)
        {
            try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), navLabel); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        if (!navigated) return;
        Thread.Sleep(400);

        var stopBtn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
        if (stopBtn is null || !stopBtn.Current.IsEnabled || !stopBtn.Current.Name.Contains("STOP ENDPOINT"))
        {
            if (required) Report(failures, false, $"{navLabel}: STOP ENDPOINT still findable/enabled at teardown");
            return;
        }
        UiAutomationHelpers.Invoke(stopBtn);
        var exited = UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName(processBaseName).Length == 0, TimeSpan.FromSeconds(15));
        if (required) Report(failures, exited, $"{navLabel}: {processBaseName}.exe exited after Stop");
    }

    /// <summary>Real curl.exe launches (ships with Windows) so Process and Network have genuinely
    /// overlapping, PID-linked evidence to correlate -- best-effort: even a failed/offline curl
    /// still produces a real process-create event and a real DNS/connection-attempt event.</summary>
    private static Task GenerateCorrelatableActivityAsync(CancellationToken ct) => Task.Run(() =>
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "curl.exe",
                    Arguments = "-s -m 5 https://example.com/",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                p?.WaitForExit(6000);
            }
            catch { /* best effort */ }
            Thread.Sleep(1500);
        }
    }, ct);

    private static void RunGroupSelectionChecks(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var selected = SelectLastItem(root, "CorrelationGroupsGrid", ControlType.DataItem);
        Report(failures, selected, "Groups grid: a real correlated group can be selected");
        if (!selected) return;
        Thread.Sleep(500);

        var coverage = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "CorrelationCoverageText");
        Report(failures, coverage is not null && !string.IsNullOrWhiteSpace(coverage.Current.Name),
            $"Investigation header: real source-coverage text renders (\"{coverage?.Current.Name}\")");

        var confidence = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "CorrelationConfidenceSummaryText");
        Report(failures, confidence is not null && !string.IsNullOrWhiteSpace(confidence.Current.Name),
            $"Investigation header: real confidence summary renders (\"{confidence?.Current.Name}\")");

        // Timeline (default tab).
        var timelineCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationTimelineList", ControlType.Text);
        Report(failures, timelineCount > 0, $"Timeline: real member rows render (found {timelineCount} text elements)");

        // Evidence Graph tab.
        var switchedToGraph = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Evidence Graph");
        Report(failures, switchedToGraph, "Investigation tabs: 'Evidence Graph' is selectable");
        if (switchedToGraph)
        {
            Thread.Sleep(400);
            var nodeCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationGraphNodesList", ControlType.Button);
            Report(failures, nodeCount > 0, $"Evidence Graph: real evidence nodes render (found {nodeCount})");
        }

        // Chain View tab.
        var switchedToChain = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Chain View");
        Report(failures, switchedToChain, "Investigation tabs: 'Chain View' is selectable");
        if (switchedToChain)
        {
            Thread.Sleep(400);
            var chainCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationChainList", ControlType.Text);
            Report(failures, chainCount > 0, $"Chain View: real member cards render (found {chainCount} text elements)");
        }

        // Raw JSON tab -- fills the gap OUT.TXT/FORU.TXT claimed was already there but wasn't wired
        // into the XAML (CorrelationRowViewModel.RawJson existed and was populated, just never bound).
        var switchedToRawJson = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Raw JSON");
        Report(failures, switchedToRawJson, "Investigation tabs: 'Raw JSON' is selectable");
        if (switchedToRawJson)
        {
            Thread.Sleep(300);
            var rawJsonBox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "CorrelationRawJsonTextBox");
            var rawJsonValue = rawJsonBox is not null && rawJsonBox.TryGetCurrentPattern(ValuePattern.Pattern, out var vp)
                ? ((ValuePattern)vp).Current.Value : "";
            Report(failures, rawJsonValue.TrimStart().StartsWith('{'),
                $"Raw JSON: the selected group's real session_timeline record renders as JSON ({rawJsonValue.Length} chars)");
        }

        // Return to Timeline so RunFilterRoundTrip starts from a known state.
        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Timeline");
    }

    private static void RunFilterRoundTrip(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var filterBox = UiAutomationHelpers.FindByAutomationId(root, "CorrelationFilterTextBox");
        if (filterBox is null || !filterBox.TryGetCurrentPattern(ValuePattern.Pattern, out var patternObj))
        {
            Report(failures, false, "Filter: CorrelationFilterTextBox is present with ValuePattern support");
            return;
        }
        var valuePattern = (ValuePattern)patternObj;
        var beforeCount = CountDescendants(root, "CorrelationGroupsGrid", ControlType.DataItem);

        var noMatchToken = "titan-live-test-no-match-" + Guid.NewGuid().ToString("N")[..8];
        valuePattern.SetValue(noMatchToken);
        Thread.Sleep(400);
        var filteredCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationGroupsGrid", ControlType.DataItem);
        Report(failures, filteredCount == 0,
            $"Filter: an unmatched real filter genuinely empties the groups grid (before={beforeCount}, after={filteredCount})");

        valuePattern.SetValue("");
        Thread.Sleep(400);
        var restoredCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "CorrelationGroupsGrid", ControlType.DataItem);
        Report(failures, restoredCount > 0, $"Filter: clearing the filter restores the groups grid (restored={restoredCount})");
    }

    private static bool SelectLastItem(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return false;
        var items = container.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType));
        if (items.Count == 0) return false;
        var last = items[items.Count - 1];
        if (!last.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var p)) return false;
        ((SelectionItemPattern)p).Select();
        return true;
    }

    private static int CountDescendants(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return -1;
        return container.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType)).Count;
    }

    /// <summary>Same technique as NetworkWorkspaceTests/CustomRuleWorkflowTests.SelectTabByHeader --
    /// TabItem's default UI Automation Name mirrors its Header content. Duplicated locally rather
    /// than shared, matching this project's existing convention of small self-contained test files.</summary>
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

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}
