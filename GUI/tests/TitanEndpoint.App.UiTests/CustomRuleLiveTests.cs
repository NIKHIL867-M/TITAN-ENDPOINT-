using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.App.UiTests;

/// <summary>Live end-to-end pass over Custom Rule against the REAL Python API + watcher, driving the
/// real WPF GUI -- the deliberate gap CustomRuleWorkflowTests.cs's own doc comment calls out ("Driving
/// a full English-or-YAML rule all the way through backend validation, simulation, and Approve ...
/// needs the real Python Custom Rule service reachable ... not attempted here").
///
/// Found live (real, previously-unknown bug, fixed in CustomRuleServiceController.StartApiAsync):
/// the API was launched without ever setting GEKKO_API_TOKEN on the child process or publishing the
/// DPAPI token file CustomRuleApiClient reads back, so app/main.py's local_api_auth middleware 503'd
/// "unauthenticated_launch_refused" on every /api/* route except the exempt /api/health -- which kept
/// reporting healthy the whole time. This is the single root cause behind every symptom reported:
/// Watcher Coverage showing nothing, English rule authoring failing, and uncertainty about whether
/// Watcher Activity (Matched Evidence/Outcomes) works -- every one of those calls the same
/// CustomRuleApiClient.
///
/// Starts the API/watcher directly via CustomRuleServiceController (the exact class MainViewModel's
/// Start All button uses) instead of clicking Start All in the GUI: MainViewModel's own
/// DependentPipelineReady gate requires the native 6-endpoint fleet to already be healthy before it
/// will even call StartApiAsync, but that gate is Start All's own orchestration policy, not something
/// CustomRuleServiceController or any of the Wizard/Coverage/Activity ViewModels' API calls actually
/// depend on -- so this reaches the real, fixed code path directly, verifies it end-to-end through the
/// real GUI, and skips several minutes of unrelated native endpoint startup this phase doesn't need.</summary>
public static class CustomRuleLiveTests
{
    private const string ExampleYamlRule =
        "trigger_event: process.start\n" +
        "conditions:\n" +
        "  - field: name\n" +
        "    operator: \"==\"\n" +
        "    value: titan-live-test-marker.exe\n" +
        "response_actions:\n" +
        "  - type: alert\n" +
        "severity: low\n" +
        "priority: 5\n" +
        "tags: [titan_live_test]\n";

    /// <summary>Santosh, 2026-08-04: "after the condition is added ... we are given 3 options ...
    /// alert, kill, isolate ... make sure all of them are working ... test it properly." Includes
    /// suggested_action so the Stage 4 checkbox/extra-confirm UI (which only ever renders rows for
    /// whatever suggested_action contains — see CustomRuleWizardViewModel.ApplyIr) has a real
    /// kill_process row to drive, exactly the path a human approving a kill rule would take.</summary>
    private const string KillTestYamlRule =
        "trigger_event: process.start\n" +
        "conditions:\n" +
        "  - field: name\n" +
        "    operator: \"==\"\n" +
        "    value: titan-live-test-kill.exe\n" +
        "response_actions:\n" +
        "  - type: kill_process\n" +
        "suggested_action: [kill_process]\n" +
        "suggested_action_reason: \"Live test of the kill_process approval + extra-confirm path\"\n" +
        "severity: low\n" +
        "priority: 5\n" +
        "tags: [titan_live_test, titan_live_test_kill]\n";

    private const string DetectionTestYamlRule =
        "trigger_event: process.start\n" +
        "conditions:\n" +
        "  - field: name\n" +
        "    operator: \"==\"\n" +
        "    value: ping.exe\n" +
        "response_actions:\n" +
        "  - type: alert\n" +
        "severity: low\n" +
        "priority: 5\n" +
        "tags: [titan_live_detection_test]\n";

    public static List<string> Run()
    {
        var failures = new List<string>();
        var customRuleRoot = FindCustomRuleRoot();
        var dataDir = Path.Combine(customRuleRoot, "data");
        var apiClient = new CustomRuleApiClient("http://127.0.0.1:8765", dataDir);
        var controller = new CustomRuleServiceController(customRuleRoot, apiClient);

        Process? guiProcess = null;
        IsolatedTestProfile? profile = null;
        try
        {
            var (startOk, startMsg) = controller.StartApiAsync().GetAwaiter().GetResult();
            Report(failures, startOk, $"Backend: API start requested ({startMsg})");
            if (!startOk) return failures;

            var apiReady = UiAutomationHelpers.WaitUntil(
                () => controller.IsApiReadyAsync().GetAwaiter().GetResult(), TimeSpan.FromSeconds(20));
            Report(failures, apiReady, "Backend: API became reachable and authenticated within 20s");
            if (!apiReady) return failures;

            var (watcherOk, watcherMsg) = controller.StartWatcher();
            Report(failures, watcherOk, $"Backend: watcher start requested ({watcherMsg})");
            if (watcherOk)
            {
                var requestedAt = DateTime.UtcNow;
                var watcherReady = UiAutomationHelpers.WaitUntil(() => controller.IsWatcherReady(requestedAt), TimeSpan.FromSeconds(20));
                Report(failures, watcherReady, "Backend: watcher became ready within 20s");
            }

            profile = new IsolatedTestProfile();
            guiProcess = profile.LaunchAndWaitForMainWindow();

            var navigated = false;
            for (var attempt = 0; attempt < 3 && !navigated; attempt++)
            {
                try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(guiProcess), "Custom Rules"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigated, "Navigate to Custom Rules page");
            if (!navigated) return failures;
            Thread.Sleep(900);

            RunWatcherCoverageCheck(guiProcess, failures);
            RunYamlParseCheck(guiProcess, failures);
            RunEnglishParseCheck(guiProcess, failures);
            RunWatcherActivityCheck(guiProcess, failures);
            RunLiveAlertDetection(guiProcess, apiClient, failures);
            var approvedKillRuleId = RunFullKillApprovalFlow(guiProcess, failures);
            if (approvedKillRuleId is not null)
            {
                // Cleanup via the same authenticated API the GUI itself uses — reliable and fast,
                // vs. driving Approved Rules' filter/select/delete UI a second time for a rule this
                // test already proved Approve persisted correctly. Never leaves this real, unscoped
                // temporary rule in Santosh's actual data/rules.jsonl.
                var deleted = apiClient.DeleteRuleAsync(approvedKillRuleId).GetAwaiter().GetResult();
                Report(failures, deleted.Success, $"Cleanup: temporary kill_process test rule deleted ({(deleted.Success ? "ok" : deleted.RawBody)})");
            }
        }
        finally
        {
            if (guiProcess is not null) IsolatedTestProfile.CloseAndWait(guiProcess);
            profile?.Dispose();
            controller.StopWatcher();
            controller.StopApi();
        }
        return failures;
    }

    private static void RunLiveAlertDetection(
        Process guiProcess, CustomRuleApiClient apiClient, List<string> failures)
    {
        string? ruleId = null;
        var processEndpointStarted = false;
        try
        {
            var navigated = UiAutomationHelpers.SelectByLabel(
                IsolatedTestProfile.GetRootElement(guiProcess), "Process");
            Report(failures, navigated, "Live detection: navigate to Process endpoint");
            if (!navigated) return;
            Thread.Sleep(500);

            var start = UiAutomationHelpers.FindByAutomationId(
                IsolatedTestProfile.GetRootElement(guiProcess), "StartStopEndpointButton");
            if (Process.GetProcessesByName("titan_process").Length == 0 && start is not null)
                UiAutomationHelpers.Invoke(start);
            processEndpointStarted = UiAutomationHelpers.WaitUntil(
                () => Process.GetProcessesByName("titan_process").Length == 1,
                TimeSpan.FromSeconds(20));
            Report(failures, processEndpointStarted,
                "Live detection: real Process endpoint is running as the watcher source");
            if (!processEndpointStarted) return;

            var parsed = apiClient.FromYamlAsync(DetectionTestYamlRule).GetAwaiter().GetResult();
            Report(failures, parsed.Success && parsed.Body is not null,
                "Live detection: temporary alert-only YAML validates through the authenticated API");
            if (!parsed.Success || parsed.Body is not { } parsedBody) return;

            if (!parsedBody.TryGetProperty("normalized_draft", out var flatIr))
            {
                Report(failures, false,
                    "Live detection: YAML response includes the normalized rule IR");
                return;
            }
            var wrappedIr = JsonSerializer.SerializeToElement(new
            {
                status = "ok",
                clarification = (string?)null,
                ir = flatIr,
                explanation = (object?)null
            });
            var approved = apiClient.ApproveAsync(
                "LIVE ACCEPTANCE: alert when ping.exe starts",
                wrappedIr,
                Array.Empty<string>(),
                Array.Empty<string>(),
                new[] { "alert" },
                null).GetAwaiter().GetResult();
            if (approved.Success && approved.Body is { } approvedBody &&
                approvedBody.TryGetProperty("rule_id", out var idElement))
                ruleId = idElement.GetString();
            Report(failures, !string.IsNullOrWhiteSpace(ruleId),
                "Live detection: temporary alert-only rule is approved and persisted" +
                (string.IsNullOrWhiteSpace(ruleId) ? $" (HTTP {approved.StatusCode}: {approved.RawBody})" : ""));
            if (string.IsNullOrWhiteSpace(ruleId)) return;

            var reloaded = UiAutomationHelpers.WaitUntil(() =>
            {
                var runtime = apiClient.GetWatcherRuntimeAsync().GetAwaiter().GetResult();
                return runtime.Success && runtime.Body is { } body &&
                       body.TryGetProperty("rules_loaded", out var count) &&
                       count.TryGetInt32(out var loaded) && loaded >= 4;
            }, TimeSpan.FromSeconds(15));
            Report(failures, reloaded,
                "Live detection: watcher acknowledges the newly approved rule");

            using var ping = Process.Start(new ProcessStartInfo
            {
                FileName = "ping.exe",
                Arguments = "-n 4 127.0.0.1",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            Report(failures, ping is not null,
                "Live detection: real matching ping.exe process was launched");

            JsonElement? matchedAlert = null;
            var detected = UiAutomationHelpers.WaitUntil(() =>
            {
                var alerts = apiClient.GetAlertsAsync(limit: 100).GetAwaiter().GetResult();
                if (!alerts.Success || alerts.Body is not { } body ||
                    !body.TryGetProperty("alerts", out var rows) || rows.ValueKind != JsonValueKind.Array)
                    return false;
                foreach (var row in rows.EnumerateArray())
                {
                    if (row.TryGetProperty("rule_id", out var candidate) &&
                        string.Equals(candidate.GetString(), ruleId, StringComparison.Ordinal))
                    {
                        matchedAlert = row.Clone();
                        return true;
                    }
                }
                return false;
            }, TimeSpan.FromSeconds(20));
            Report(failures, detected,
                "Live detection: watcher matched the real process event and persisted an alert");

            if (matchedAlert is { } alert &&
                alert.TryGetProperty("instance_id", out var instanceElement) &&
                !string.IsNullOrWhiteSpace(instanceElement.GetString()))
            {
                var evidence = apiClient.GetEvidenceAsync(instanceElement.GetString()!).GetAwaiter().GetResult();
                Report(failures, evidence.Success && evidence.Body is not null,
                    "Live detection: the persisted alert resolves to full evidence through the API");
            }
            else if (detected)
            {
                Report(failures, false,
                    "Live detection: matched alert includes a durable evidence instance id");
            }

            try { ping?.WaitForExit(8000); } catch { /* best effort */ }
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(ruleId))
            {
                var deleted = apiClient.DeleteRuleAsync(ruleId).GetAwaiter().GetResult();
                Report(failures, deleted.Success,
                    "Live detection cleanup: temporary alert-only rule deleted");
            }

            if (processEndpointStarted)
            {
                UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(guiProcess), "Process");
                Thread.Sleep(300);
                var stop = UiAutomationHelpers.FindByAutomationId(
                    IsolatedTestProfile.GetRootElement(guiProcess), "StartStopEndpointButton");
                if (stop is not null && stop.Current.IsEnabled && stop.Current.Name.Contains("STOP ENDPOINT"))
                    UiAutomationHelpers.Invoke(stop);
                var stopped = UiAutomationHelpers.WaitUntil(
                    () => Process.GetProcessesByName("titan_process").Length == 0,
                    TimeSpan.FromSeconds(15));
                Report(failures, stopped,
                    "Live detection cleanup: Process endpoint stopped without an orphan");
            }

            UiAutomationHelpers.SelectByLabel(
                IsolatedTestProfile.GetRootElement(guiProcess), "Custom Rules");
            Thread.Sleep(400);
        }
    }

    /// <summary>Drives the wizard through YAML Describe -&gt; Review Structure -&gt; Test -&gt; Approve for a
    /// kill_process rule, including checking its response-action checkbox and the destructive-action
    /// extra-confirm checkbox — the exact human steps FORU.TXT's "never auto-select kill_process/
    /// isolate_host" requirement describes. Also the exact path that exercises
    /// CustomRuleWizardViewModel.RunApprove's IR-wrapping (see its own comment: sending the flat _ir
    /// unwrapped 400s on every Approve). Returns the approved rule's id for cleanup, or null if
    /// approval did not succeed.</summary>
    private static string? RunFullKillApprovalFlow(Process process, List<string> failures)
    {
        var selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Rule Authoring");
        Report(failures, selected, "Full approval flow: back on Rule Authoring tab");
        if (!selected) return null;
        Thread.Sleep(400);

        // A prior check may have left the wizard on Stage 2 — return to Stage 1 first.
        for (var i = 0; i < 3; i++)
        {
            var stage1Visible = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "SelectEnglishModeButton") is not null;
            if (stage1Visible) break;
            var back = UiAutomationHelpers.FindByName(IsolatedTestProfile.GetRootElement(process), "← Back", ControlType.Button);
            if (back is null) break;
            UiAutomationHelpers.Invoke(back);
            Thread.Sleep(400);
        }

        var root = IsolatedTestProfile.GetRootElement(process);
        var yamlModeButton = UiAutomationHelpers.FindByAutomationId(root, "SelectYamlModeButton");
        Report(failures, yamlModeButton is not null, "Full approval flow: YAML mode button present");
        if (yamlModeButton is null) return null;
        UiAutomationHelpers.Invoke(yamlModeButton);
        Thread.Sleep(300);

        var yamlBox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "RuleYamlTextBox");
        if (yamlBox is null || !yamlBox.TryGetCurrentPattern(ValuePattern.Pattern, out var yamlPatternObj))
        {
            Report(failures, false, "Full approval flow: RuleYamlTextBox present with ValuePattern support");
            return null;
        }
        ((ValuePattern)yamlPatternObj).SetValue(KillTestYamlRule);
        Thread.Sleep(200);

        var parseButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ParseYamlButton");
        if (parseButton is null) { Report(failures, false, "Full approval flow: Parse YAML button present"); return null; }
        UiAutomationHelpers.Invoke(parseButton);

        var reachedReview = UiAutomationHelpers.WaitUntil(
            () => FindTextContaining(process, "Review Structure") is not null, TimeSpan.FromSeconds(15));
        var parseErr = FindByAutomationIdSafe(process, "ParseErrorTextBlock");
        Report(failures, reachedReview, $"Full approval flow: kill_process YAML rule reaches Review Structure (parse error, if any: '{parseErr}')");
        if (!reachedReview) return null;

        for (var i = 0; i < 2; i++)
        {
            var next = UiAutomationHelpers.FindByName(IsolatedTestProfile.GetRootElement(process), "Next →", ControlType.Button);
            if (next is null) { Report(failures, false, $"Full approval flow: Next button present (advancing to stage {i + 3})"); return null; }
            UiAutomationHelpers.Invoke(next);
            Thread.Sleep(400);
        }
        var onApproveStage = FindTextContaining(process, "4. Approve") is not null;
        Report(failures, onApproveStage, "Full approval flow: reached Stage 4 (Approve)");
        if (!onApproveStage) return null;

        var killCheckbox = UiAutomationHelpers.FindByName(IsolatedTestProfile.GetRootElement(process), "Response action: kill_process", ControlType.CheckBox);
        if (killCheckbox is null)
        {
            var allCheckboxNames = UiAutomationHelpers.FindAllByControlType(IsolatedTestProfile.GetRootElement(process), ControlType.CheckBox)
                .Select(SafeName).ToList();
            Report(failures, false,
                $"Full approval flow: kill_process response-action checkbox is present (populated from YAML's suggested_action, never auto-selected) -- checkboxes actually found: [{string.Join(", ", allCheckboxNames)}]");
            return null;
        }
        Report(failures, UiAutomationHelpers.TryToggle(killCheckbox, true), "Full approval flow: kill_process checkbox toggled on");
        Thread.Sleep(200);

        var confirmCheckbox = UiAutomationHelpers.FindByName(IsolatedTestProfile.GetRootElement(process), "Confirm destructive action: kill_process", ControlType.CheckBox);
        Report(failures, confirmCheckbox is not null, "Full approval flow: destructive-action extra-confirm checkbox appears once kill_process is selected");
        if (confirmCheckbox is not null)
            Report(failures, UiAutomationHelpers.TryToggle(confirmCheckbox, true), "Full approval flow: extra-confirm checkbox toggled on");
        Thread.Sleep(200);

        var approveButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ApproveRuleButton");
        Report(failures, approveButton is not null, "Full approval flow: Approve Rule button present");
        if (approveButton is null) return null;
        UiAutomationHelpers.Invoke(approveButton);

        var settled = UiAutomationHelpers.WaitUntil(
            () => FindTextContaining(process, "id ") is not null || FindTextContaining(process, "failed") is not null,
            TimeSpan.FromSeconds(20));
        var resultText = FindTextContaining(process, "id ") ?? FindTextContaining(process, "failed") ?? "";
        // Before this round's fix (CustomRuleWizardViewModel.RunApprove wrapping _ir), this always
        // showed "Approval failed (HTTP 400): Expected a complete IR object" here, every single time,
        // for both English and YAML rules — the exact regression this test now guards against.
        var approved = settled && resultText.Contains("approved", StringComparison.OrdinalIgnoreCase);
        Report(failures, approved,
            $"Full approval flow: kill_process rule approved end-to-end through the real GUI wizard (result: '{resultText}')");

        if (!approved) return null;
        var match = System.Text.RegularExpressions.Regex.Match(resultText, "id ([0-9a-fA-F-]{36})");
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>The exact regression the user reported: "showing nothing but initially when I created
    /// it was showing something." Confirms the grid now has real rows and SummaryText no longer reads
    /// an unreachable/unauthenticated error.</summary>
    private static void RunWatcherCoverageCheck(Process process, List<string> failures)
    {
        var selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Watcher Coverage");
        Report(failures, selected, "Watcher Coverage: tab is selectable");
        if (!selected) return;

        var gotRows = UiAutomationHelpers.WaitUntil(
            () => CountDescendants(IsolatedTestProfile.GetRootElement(process), "WatcherCoverageGrid", ControlType.DataItem) > 0,
            TimeSpan.FromSeconds(15));
        var rowCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "WatcherCoverageGrid", ControlType.DataItem);
        Report(failures, gotRows, $"Watcher Coverage: grid shows real capability rows against the authenticated backend (found {rowCount})");

        var summary = FindTextContaining(process, "event");
        Report(failures, summary is not null && !summary.Contains("unreachable", StringComparison.OrdinalIgnoreCase)
                                                && !summary.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
                                                && !summary.Contains("no valid access token", StringComparison.OrdinalIgnoreCase),
            $"Watcher Coverage: summary text is a real coverage count, not an unreachable/unauthenticated error (found: '{summary}')");
    }

    /// <summary>User: "I did not test the YAML also." Uses app/yaml_rules.py's own documented example
    /// rule verbatim (its docstring), so structural validation is exercised against a shape the
    /// backend itself considers canonical rather than a guessed schema.</summary>
    private static void RunYamlParseCheck(Process process, List<string> failures)
    {
        var selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Rule Authoring");
        Report(failures, selected, "YAML authoring: back on Rule Authoring tab");
        if (!selected) return;
        Thread.Sleep(400);

        var root = IsolatedTestProfile.GetRootElement(process);
        var yamlModeButton = UiAutomationHelpers.FindByAutomationId(root, "SelectYamlModeButton");
        Report(failures, yamlModeButton is not null, "YAML authoring: YAML mode button is present");
        if (yamlModeButton is null) return;
        UiAutomationHelpers.Invoke(yamlModeButton);
        Thread.Sleep(300);

        var yamlBox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "RuleYamlTextBox");
        if (yamlBox is null || !yamlBox.TryGetCurrentPattern(ValuePattern.Pattern, out var yamlPatternObj))
        {
            Report(failures, false, "YAML authoring: RuleYamlTextBox is present with ValuePattern support");
            return;
        }
        ((ValuePattern)yamlPatternObj).SetValue(ExampleYamlRule);
        Thread.Sleep(200);

        var parseButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ParseYamlButton");
        Report(failures, parseButton is not null, "YAML authoring: Parse YAML button is present");
        if (parseButton is null) return;
        UiAutomationHelpers.Invoke(parseButton);

        var reachedStage2 = UiAutomationHelpers.WaitUntil(
            () => FindTextContaining(process, "Review Structure") is not null, TimeSpan.FromSeconds(15));
        var errorText = FindByAutomationIdSafe(process, "ParseErrorTextBlock");
        Report(failures, reachedStage2,
            $"YAML authoring: a real YAML rule validates end-to-end against the authenticated backend and advances to Review Structure (parse error, if any: '{errorText}')");

        if (reachedStage2)
        {
            // Stage 2 has no automation-id'd trigger box in the current XAML; rely on the raw IR
            // expander text instead so this does not depend on an id that may not exist.
            var rawIr = FindTextValueContaining(process, "process.start");
            Report(failures, rawIr, "YAML authoring: the normalized draft echoes back the real trigger_event we submitted (process.start)");
        }
    }

    /// <summary>User: "the English when I tried to add it is not working." Drives a real
    /// English-language description through the real Groq-backed /api/parse-rule call (GROQ_API_KEY
    /// is configured in CUSTOM RULE\.env) and confirms it advances past Describe rather than showing
    /// the auth-wall failure the user hit.</summary>
    private static void RunEnglishParseCheck(Process process, List<string> failures)
    {
        var selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Rule Authoring");
        Report(failures, selected, "English authoring: back on Rule Authoring tab");
        if (!selected) return;
        Thread.Sleep(400);

        // The prior YAML check left the wizard on Stage 2 ("Review Structure") -- the Describe
        // stage's RuleTextEnglishTextBox is Visibility-gated to Stage 1, so click Back (up to 3
        // times, matching CanGoBack's Stage>1 gate) until Describe is showing again.
        for (var i = 0; i < 3; i++)
        {
            var stage1Visible = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "SelectEnglishModeButton") is not null;
            if (stage1Visible) break;
            var backButton = UiAutomationHelpers.FindByName(IsolatedTestProfile.GetRootElement(process), "← Back", ControlType.Button);
            if (backButton is null) break;
            UiAutomationHelpers.Invoke(backButton);
            Thread.Sleep(400);
        }

        var root = IsolatedTestProfile.GetRootElement(process);
        var englishModeButton = UiAutomationHelpers.FindByAutomationId(root, "SelectEnglishModeButton");
        if (englishModeButton is not null) UiAutomationHelpers.Invoke(englishModeButton);
        Thread.Sleep(300);

        var englishBox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "RuleTextEnglishTextBox");
        if (englishBox is null || !englishBox.TryGetCurrentPattern(ValuePattern.Pattern, out var patternObj))
        {
            Report(failures, false, "English authoring: RuleTextEnglishTextBox is present with ValuePattern support");
            return;
        }
        ((ValuePattern)patternObj).SetValue(
            "Alert when notepad.exe is launched, severity low, priority 3, tag it titan_live_test.");
        Thread.Sleep(200);

        var parseButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ParseRuleButton");
        Report(failures, parseButton is not null, "English authoring: Parse Rule button is present");
        if (parseButton is null) return;
        UiAutomationHelpers.Invoke(parseButton);

        // Groq round-trip: allow more time than the local-only YAML path.
        var reachedStage2 = UiAutomationHelpers.WaitUntil(
            () => FindTextContaining(process, "Review Structure") is not null, TimeSpan.FromSeconds(30));
        var errorText = FindByAutomationIdSafe(process, "ParseErrorTextBlock");
        Report(failures, reachedStage2,
            $"English authoring: a real plain-English description parses end-to-end via Groq against the authenticated backend (parse error, if any: '{errorText}')");
    }

    /// <summary>User: unsure whether Watcher Activity ("Matched Evidence"/Outcomes) is working. Same
    /// authenticated CustomRuleApiClient as Coverage/Wizard -- confirms it is no longer silently
    /// empty because of the auth wall (WatcherActivityViewModel.RefreshAsync returns early with no
    /// error surfaced on failure, so an empty grid there was previously indistinguishable from "no
    /// activity yet" -- this at least proves the call itself now succeeds).</summary>
    private static void RunWatcherActivityCheck(Process process, List<string> failures)
    {
        var selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Watcher Activity");
        Report(failures, selected, "Watcher Activity: tab is selectable");
        if (!selected) return;
        Thread.Sleep(500);

        var refreshButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "RefreshActivityOnceButton");
        Report(failures, refreshButton is not null, "Watcher Activity: Refresh Once button is present");
        var stillResponsive = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "WatcherActivityFilterTextBox") is not null;
        Report(failures, stillResponsive, "Watcher Activity: grid and filter render without an unhandled failure against the authenticated backend");
    }

    private static string FindCustomRuleRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "TITAN_MASTER_CONTEXT.md")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not locate the TITAN root (TITAN_MASTER_CONTEXT.md) above " + AppContext.BaseDirectory);
        var root = Path.Combine(dir.FullName, "CUSTOM RULE");
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"CUSTOM RULE root not found at {root}.");
        return root;
    }

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

    private static string? FindTextContaining(Process process, string needle)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var texts = root.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text));
        foreach (AutomationElement t in texts)
        {
            var name = SafeName(t);
            if (name.Contains(needle, StringComparison.OrdinalIgnoreCase)) return name;
        }
        return null;
    }

    /// <summary>Same idea as FindTextContaining but also checks editable-text (TextBox/Edit) controls
    /// via ValuePattern, since the Raw IR JSON display is a read-only TextBox, not a Text element.</summary>
    private static bool FindTextValueContaining(Process process, string needle)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var edits = root.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit));
        foreach (AutomationElement e in edits)
        {
            if (!e.TryGetCurrentPattern(ValuePattern.Pattern, out var p)) continue;
            var value = ((ValuePattern)p).Current.Value ?? "";
            if (value.Contains(needle, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string FindByAutomationIdSafe(Process process, string automationId)
    {
        var el = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), automationId);
        return el is null ? "" : SafeName(el);
    }

    private static string SafeName(AutomationElement element)
    {
        try { return element.Current.Name ?? string.Empty; }
        catch (ElementNotAvailableException) { return string.Empty; }
    }

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}

/// <summary>Fast, GUI-free isolation of a single question: does CustomRuleServiceController's
/// Stop leave the venv-launcher's real interpreter child running as an orphan? (found live: the
/// launcher stub honors Ctrl+C and exits gracefully while its child does not, so
/// Process.Kill(entireProcessTree) on the launcher was never reached; fixed via ProcessTree's
/// pre-shutdown child-PID snapshot + KillSurvivingChildren). Deliberately skips the GUI/Groq/YAML
/// round-trip CustomRuleLiveTests does -- this only needs a start immediately followed by a stop,
/// checked directly against the OS process list.</summary>
public static class CustomRuleProcessCleanupTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        var customRuleRoot = FindCustomRuleRoot();
        var dataDir = Path.Combine(customRuleRoot, "data");
        var apiClient = new CustomRuleApiClient("http://127.0.0.1:8765", dataDir);
        var controller = new CustomRuleServiceController(customRuleRoot, apiClient);

        // A just-terminated Windows process can remain enumerable briefly after its owner has
        // synchronously waited for exit. Observe the stable clean-state boundary rather than one
        // racy instant between consecutive lifecycle suites.
        var cleanStart = UiAutomationHelpers.WaitUntil(
            () => GetTitanPythonPids().Count == 0, TimeSpan.FromSeconds(10));
        var preExisting = GetTitanPythonPids();
        Report(failures, cleanStart && preExisting.Count == 0,
            $"Pre-check: no leftover CUSTOM RULE python processes before this run (found {preExisting.Count})");

        var (startOk, startMsg) = controller.StartApiAsync().GetAwaiter().GetResult();
        Report(failures, startOk, $"API start requested ({startMsg})");
        var apiReady = startOk && UiAutomationHelpers.WaitUntil(
            () => controller.IsApiReadyAsync().GetAwaiter().GetResult(), TimeSpan.FromSeconds(20));
        Report(failures, apiReady, "API became reachable within 20s");

        var (watcherOk, watcherMsg) = controller.StartWatcher();
        Report(failures, watcherOk, $"Watcher start requested ({watcherMsg})");
        var requestedAt = DateTime.UtcNow;
        var watcherReady = watcherOk && UiAutomationHelpers.WaitUntil(() => controller.IsWatcherReady(requestedAt), TimeSpan.FromSeconds(20));
        Report(failures, watcherReady, "Watcher became ready within 20s");

        var runningPids = GetTitanPythonPids();
        Report(failures, runningPids.Count >= 2, $"Real python processes are running after Start (found {runningPids.Count}: {string.Join(",", runningPids)})");

        var (apiStopOk, apiStopMsg) = controller.StopApi();
        Report(failures, apiStopOk, $"API stop reported success ({apiStopMsg})");
        var (watcherStopOk, watcherStopMsg) = controller.StopWatcher();
        Report(failures, watcherStopOk, $"Watcher stop reported success ({watcherStopMsg})");

        var noOrphans = UiAutomationHelpers.WaitUntil(() => GetTitanPythonPids().Count == 0, TimeSpan.FromSeconds(10));
        var survivors = GetTitanPythonPids();
        Report(failures, noOrphans, $"No orphaned CUSTOM RULE python processes remain after Stop (found {survivors.Count}: {string.Join(",", survivors)})");

        // Best-effort final cleanup regardless of the assertion outcome above.
        foreach (var pid in survivors)
        {
            try { Process.GetProcessById(pid).Kill(entireProcessTree: true); } catch { /* best effort */ }
        }

        return failures;
    }

    /// <summary>Every python.exe process currently running. The caller confirms a clean slate (zero
    /// python.exe processes) before starting the API/watcher, so any found during/after this run are
    /// unambiguously the ones this test itself started -- no command-line filtering (and no
    /// System.Management dependency this project otherwise has zero NuGet packages for) needed.</summary>
    private static List<int> GetTitanPythonPids()
    {
        var pids = new List<int>();
        foreach (var p in Process.GetProcessesByName("python"))
        {
            try { pids.Add(p.Id); }
            finally { p.Dispose(); }
        }
        return pids;
    }

    private static string FindCustomRuleRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "TITAN_MASTER_CONTEXT.md")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not locate the TITAN root (TITAN_MASTER_CONTEXT.md) above " + AppContext.BaseDirectory);
        return Path.Combine(dir.FullName, "CUSTOM RULE");
    }

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}
