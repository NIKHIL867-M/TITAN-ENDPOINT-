using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>FORU.TXT 0.8 "Custom Rule suite: test all six workflows, English authoring, YAML without
/// LLM, import/export, parse errors, structured edits, stale simulation invalidation, capability
/// gaps, human approval, watcher reload, rule search/detail/promote/delete, evidence, activity
/// pause/resume, outcomes, destructive confirmation, and rollback."
///
/// This is a deliberately partial first pass, not the full gate: it verifies every one of the
/// CustomRulesView's five tabs renders its real, distinguishing controls (the five tabs cover all
/// six workflows -- Matched Evidence and Response Outcomes are deliberately unified onto the Alerts
/// page rather than duplicated, as CustomRulesView.xaml's own "Matched Evidence &amp; Outcomes" tab
/// explains), that switching between the wizard's English and YAML authoring modes actually swaps
/// which text control is present (not just which is visually styled as active), and that submitting
/// empty YAML produces a real, on-screen "review error" rather than an unhandled failure -- exactly
/// the FORU.TXT requirement "Invalid structured JSON is shown as a review error rather than causing
/// an unhandled GUI failure," tested via the one parse-error path that is deterministic without a
/// running Custom Rule backend (RunParseYaml short-circuits on empty input before making any network
/// call). Driving a full English-or-YAML rule all the way through backend validation, simulation,
/// and Approve -- which needs the real Python Custom Rule service reachable and a rule body that
/// matches its actual accepted schema -- is FORU.TXT's own Phase 1 System Acceptance item ("Create
/// and approve a YAML rule, observe watcher reload, produce a dry-run and permitted live alert"), not
/// attempted here. Promote/Delete/Delete Duplicates/Delete All are verified present and correctly
/// labelled but not invoked, since they mutate the real Custom Rule data store and
/// IsolatedTestProfile does not redirect it (see its own doc comment) -- exercising them destructively
/// against whatever real approved rules exist on this machine belongs in a live/elevated acceptance
/// pass with its own disposable fixture data, not this suite.</summary>
public static class CustomRuleWorkflowTests
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
                try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), "Custom Rules"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigated, "Navigate to Custom Rules page");
            if (!navigated) return failures;
            Thread.Sleep(900);

            RunTabInventory(process, failures);
            RunModeSwitching(process, failures);
            RunEmptyYamlParseError(process, failures);
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process);
        }
        return failures;
    }

    // (TabHeader, AutomationIds expected present once that tab is selected)
    private static readonly (string TabHeader, string[] AutomationIds)[] TabExpectations =
    {
        ("Rule Authoring", new[] { "SelectEnglishModeButton", "SelectYamlModeButton" }),
        ("Watcher Coverage", new[] { "WatcherCoverageFilterTextBox", "WatcherCoverageGrid", "RefreshCoverageButton" }),
        ("Approved Rules", new[] { "ApprovedRulesGrid", "PromoteRuleButton", "DeleteSelectedRuleButton", "DeleteDuplicateRulesButton", "DeleteAllRulesButton" }),
        ("Watcher Activity", new[] { "WatcherActivityFilterTextBox", "WatcherActivityGrid", "ToggleLiveActivityButton", "RefreshActivityOnceButton" }),
    };

    private static void RunTabInventory(System.Diagnostics.Process process, List<string> failures)
    {
        foreach (var (header, ids) in TabExpectations)
        {
            var selected = false;
            for (var attempt = 0; attempt < 3 && !selected; attempt++)
            {
                try { selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), header); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, selected, $"Custom Rule tab '{header}' is selectable");
            if (!selected) continue;
            Thread.Sleep(500);

            var root = IsolatedTestProfile.GetRootElement(process);
            foreach (var id in ids)
            {
                var found = UiAutomationHelpers.FindByAutomationId(root, id) is not null;
                Report(failures, found, $"Custom Rule tab '{header}' shows control '{id}'");
            }
        }

        // Matched Evidence & Outcomes has no interactive controls of its own by design (see class
        // doc comment) -- its distinguishing content is the explanatory redirect text.
        var evidenceTabSelected = false;
        for (var attempt = 0; attempt < 3 && !evidenceTabSelected; attempt++)
        {
            try { evidenceTabSelected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Matched Evidence & Outcomes"); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        Report(failures, evidenceTabSelected, "Custom Rule tab 'Matched Evidence & Outcomes' is selectable");
        if (evidenceTabSelected)
        {
            Thread.Sleep(500);
            var root = IsolatedTestProfile.GetRootElement(process);
            var explainer = UiAutomationHelpers.FindAllByControlType(root, ControlType.Text)
                .Any(e => SafeName(e).Contains("Alerts", StringComparison.OrdinalIgnoreCase) &&
                          SafeName(e).Contains("Evidence", StringComparison.OrdinalIgnoreCase));
            Report(failures, explainer,
                "Custom Rule tab 'Matched Evidence & Outcomes' explains that this workflow lives on the Alerts & Evidence page " +
                "(FORU.TXT: unified as one record rather than duplicated as a second table)");
        }
    }

    private static void RunModeSwitching(System.Diagnostics.Process process, List<string> failures)
    {
        var selected = false;
        for (var attempt = 0; attempt < 3 && !selected; attempt++)
        {
            try { selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Rule Authoring"); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        Report(failures, selected, "Mode switching: back on Rule Authoring tab");
        if (!selected) return;
        Thread.Sleep(500);

        var root = IsolatedTestProfile.GetRootElement(process);
        var englishBoxDefault = UiAutomationHelpers.FindByAutomationId(root, "RuleTextEnglishTextBox");
        var yamlBoxDefault = UiAutomationHelpers.FindByAutomationId(root, "RuleYamlTextBox");
        Report(failures, englishBoxDefault is not null,
            "Mode switching: English description box is present by default (default mode is English, not YAML)");
        Report(failures, yamlBoxDefault is null,
            "Mode switching: YAML box is NOT present while in English mode (Visibility-gated, not just visually de-emphasized)");

        var yamlModeButton = UiAutomationHelpers.FindByAutomationId(root, "SelectYamlModeButton");
        Report(failures, yamlModeButton is not null, "Mode switching: YAML mode button is present");
        if (yamlModeButton is null) return;
        UiAutomationHelpers.Invoke(yamlModeButton);
        Thread.Sleep(400);

        var rootAfterYaml = IsolatedTestProfile.GetRootElement(process);
        var yamlBoxAfter = UiAutomationHelpers.FindByAutomationId(rootAfterYaml, "RuleYamlTextBox");
        var englishBoxAfter = UiAutomationHelpers.FindByAutomationId(rootAfterYaml, "RuleTextEnglishTextBox");
        Report(failures, yamlBoxAfter is not null, "Mode switching: YAML box appears after selecting YAML mode");
        Report(failures, englishBoxAfter is null, "Mode switching: English box disappears after selecting YAML mode");

        var englishModeButton = UiAutomationHelpers.FindByAutomationId(rootAfterYaml, "SelectEnglishModeButton");
        Report(failures, englishModeButton is not null, "Mode switching: English mode button is still present in YAML mode");
        if (englishModeButton is null) return;
        UiAutomationHelpers.Invoke(englishModeButton);
        Thread.Sleep(400);

        var rootAfterEnglish = IsolatedTestProfile.GetRootElement(process);
        var englishBoxRestored = UiAutomationHelpers.FindByAutomationId(rootAfterEnglish, "RuleTextEnglishTextBox");
        var yamlBoxRestored = UiAutomationHelpers.FindByAutomationId(rootAfterEnglish, "RuleYamlTextBox");
        Report(failures, englishBoxRestored is not null, "Mode switching: switching back to English mode restores the English box");
        Report(failures, yamlBoxRestored is null, "Mode switching: switching back to English mode hides the YAML box again");

        // ApproveRuleButton must not exist yet -- authoring hasn't even parsed a draft, let alone
        // validated and simulated one (FORU.TXT: "Test/Approve remain blocked until the
        // authenticated backend validates, capability-checks, normalizes, and re-simulates").
        var approveButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ApproveRuleButton");
        Report(failures, approveButton is null,
            "Mode switching: Approve Rule button is correctly absent before any draft has been parsed and validated");
    }

    private static void RunEmptyYamlParseError(System.Diagnostics.Process process, List<string> failures)
    {
        var selected = false;
        for (var attempt = 0; attempt < 3 && !selected; attempt++)
        {
            try { selected = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Rule Authoring"); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        if (!selected) { Report(failures, false, "Empty YAML: on Rule Authoring tab"); return; }
        Thread.Sleep(400);

        var root = IsolatedTestProfile.GetRootElement(process);
        var yamlModeButton = UiAutomationHelpers.FindByAutomationId(root, "SelectYamlModeButton");
        if (yamlModeButton is null) { Report(failures, false, "Empty YAML: YAML mode button is present"); return; }
        UiAutomationHelpers.Invoke(yamlModeButton);
        Thread.Sleep(400);

        var parseButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ParseYamlButton");
        Report(failures, parseButton is not null, "Empty YAML: Parse YAML button is present");
        if (parseButton is null) return;

        // RuleYamlTextBox starts empty on a fresh draft -- click Parse without typing anything.
        // RunParseYaml short-circuits synchronously on empty/whitespace input before ever calling
        // the Custom Rule backend, so this is deterministic regardless of whether that service is
        // reachable -- exactly the FORU.TXT requirement that invalid input "is shown as a review
        // error rather than causing an unhandled GUI failure," not a network-dependent check.
        UiAutomationHelpers.Invoke(parseButton);
        Thread.Sleep(300);

        var errorText = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ParseErrorTextBlock");
        Report(failures, errorText is not null, "Empty YAML: parse-error text control is present");
        var message = errorText is null ? "" : SafeName(errorText);
        // WPF's default TextBlock automation Name mirrors its Text content, but fall back to the
        // Text property directly (via AutomationElement's HelpText is not applicable here) if a
        // future explicit AutomationProperties.Name override ever changes that -- Current.Name is
        // the correct primary source since no such override exists on this control today.
        Report(failures, message.Contains("YAML", StringComparison.OrdinalIgnoreCase) && message.Contains("before", StringComparison.OrdinalIgnoreCase),
            $"Empty YAML: submitting an empty draft shows a real, specific review error (found: '{message}'), not a silent no-op or unhandled exception");

        // The app must still be fully responsive afterward -- re-find a known-stable control to
        // prove the click didn't leave the UI thread stuck or the window in a broken state.
        var stillResponsive = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "SelectEnglishModeButton") is not null;
        Report(failures, stillResponsive, "Empty YAML: the wizard remains fully interactive after the parse error (no unhandled GUI failure)");
    }

    /// <summary>TabItem's default UI Automation Name mirrors its Header content (a literal string
    /// here), so this can select by ControlType.TabItem + Name directly -- unlike the primary nav
    /// rail's ListBoxItems, which need the find-Text-then-walk-up-to-SelectionItem technique in
    /// UiAutomationHelpers.SelectByLabel because their accessible Name is not header-derived.</summary>
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
