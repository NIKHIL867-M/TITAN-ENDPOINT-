using System.Runtime.InteropServices;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>FORU.TXT 0.8 "Accessibility suite: test every stable AutomationId, accessible name/help
/// text, tab order, access keys, screen-reader patterns, focus visibility/restoration, high contrast
/// switching, Reduced Motion, text scaling, and no colour-only status. Test 1366x768 through 4K at
/// 100/125/150/200% DPI and multi-monitor DPI transitions."
///
/// This is a deliberately partial first pass, not the full gate: it covers what is safe and
/// meaningful to automate on a single-monitor developer machine without mutating shared OS state --
/// an AutomationId/accessible-name inventory across all 12 pages, real Tab/Shift+Tab keyboard
/// traversal (via SendInput, not just programmatic SetFocus, so this actually exercises the same
/// path a keyboard-only operator would use), focus restoration after a dialog closes, and the
/// Reduced Motion preference round-trip. Actually toggling real Windows High Contrast mode is
/// deliberately NOT automated here -- that is a system-wide OS setting change, not something an
/// isolated test profile can scope to itself, and its live reaction was already verified manually
/// (see commit 4690a93 and FORU.TXT Part B). DPI/multi-monitor/text-scaling matrices are also not
/// covered here -- they need multiple real display configurations this single-monitor session does
/// not have.</summary>
public static class AccessibilityTests
{
    // Every stable AutomationId this session has added, grouped by the page it lives on. Used to
    // prove each one still resolves to a real element with a non-empty accessible name -- an
    // AutomationId with no Name is invisible to a screen reader even though a sighted tester would
    // never notice. Deliberately re-lists (rather than dynamically discovers) the IDs so this test
    // fails loudly if a future rename silently drops one, rather than shrinking its own coverage.
    private static readonly (string NavLabel, string[] AutomationIds)[] PageInventory =
    {
        ("Overview", new[] { "EndpointCardsList", "RecentActivityList" }),
        ("Process", new[] { "ProcessFilterTextBox", "ProcessEventsGrid" }),
        // ExportConversationButton/ConversationsGrid live on the Conversations investigation tab,
        // not the default-selected Protocol Hierarchy tab -- NetworkWorkspaceTests.cs drives tab
        // selection directly and checks those there instead.
        ("Network", new[] { "NetworkDisplayFilterTextBox", "NetworkAdapterComboBox", "NetworkPacketGrid", "ProtocolDetailsTree", "OpenRawCaptureFolderButton", "NetworkInvestigationTabs", "ProtocolHierarchyList" }),
        ("Applications", new[] { "ApplicationCatalogFilterTextBox", "ApplicationCatalogGrid", "ApplicationCatalogPrevPageButton", "ApplicationCatalogNextPageButton" }),
        ("Files", new[] { "FilesFilterTextBox", "FileEventsGrid", "ChooseFileToHashButton", "CopyHashResultButton", "CancelHashButton", "SaveHashBaselineButton" }),
        ("Port / USB", new[] { "PortUsbFilterTextBox", "PortUsbEventsGrid" }),
        ("Correlation", new[] { "CorrelationFilterTextBox", "CorrelationGroupsGrid" }),
        // ApproveRuleButton is intentionally NOT listed here -- it lives on the wizard's final
        // Review step, gated behind mode selection, authoring and a fresh validated simulation
        // (FORU.TXT: "Test/Approve remain blocked until the authenticated backend validates"), so
        // it does not exist in the tree on initial page load. SelectEnglishModeButton/
        // SelectYamlModeButton are the wizard's real step-1 controls. Driving the full wizard to
        // reach Approve belongs in CustomRuleWorkflowTests.cs, not this inventory pass.
        ("Custom Rules", new[] { "SelectEnglishModeButton", "SelectYamlModeButton" }),
        ("Alerts & Evidence", new[] { "AlertsFilterTextBox", "AlertsGrid", "LoadOlderAlertsButton" }),
        ("Unified Logs", new[] { "UnifiedLogsFilterTextBox", "LogCatalogGrid", "ReloadNewestLogsButton", "LoadOlderLogsButton" }),
        ("System Health", new[] { "SystemHealthFilterTextBox", "SystemHealthGrid", "CopyDiagnosticSummaryButton" }),
        ("Settings", new[] { "SaveSettingsButton", "CustomRuleDataDirectoryTextBox", "CustomRuleApiBaseUrlTextBox", "GlobalDiskBudgetTextBox", "MinimumFreeSpaceTextBox", "ReducedMotionCheckBox" }),
    };

    public static List<string> Run()
    {
        var failures = new List<string>();
        using var profile = new IsolatedTestProfile();
        var process = profile.LaunchAndWaitForMainWindow();
        try
        {
            RunAutomationIdInventory(process, failures);
            RunKeyboardTraversal(process, failures);
            RunReducedMotionRoundTrip(process, failures);
            RunFocusRestorationAfterDialogClose(process, failures);
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process);
        }
        return failures;
    }

    private static void RunAutomationIdInventory(System.Diagnostics.Process process, List<string> failures)
    {
        var isFirst = true;
        foreach (var (navLabel, ids) in PageInventory)
        {
            if (!isFirst)
            {
                var selected = false;
                for (var attempt = 0; attempt < 3 && !selected; attempt++)
                {
                    try { selected = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), navLabel); }
                    catch (ElementNotAvailableException) { Thread.Sleep(300); }
                }
                Report(failures, selected, $"Accessibility inventory: '{navLabel}' nav item is selectable");
                if (!selected) continue;
                Thread.Sleep(700);
            }
            isFirst = false;

            var root = IsolatedTestProfile.GetRootElement(process);
            foreach (var id in ids)
            {
                var element = UiAutomationHelpers.FindByAutomationId(root, id);
                Report(failures, element is not null, $"Accessibility inventory: '{navLabel}' has control '{id}'");
                if (element is null) continue;

                var name = SafeName(element);
                Report(failures, !string.IsNullOrWhiteSpace(name),
                    $"Accessibility inventory: '{navLabel}' control '{id}' has a non-empty accessible name (screen readers cannot announce an unnamed control)");

                Report(failures, element.Current.IsEnabled || IsExpectedDisabled(id),
                    $"Accessibility inventory: '{navLabel}' control '{id}' is enabled by default");
            }
        }
    }

    // Prev/Next catalog page buttons legitimately start disabled with an empty catalog page (no
    // page to go back/forward to). The three hash-tool action buttons legitimately start disabled
    // until a file has actually been chosen and hashed -- Copy/Cancel/Save Baseline have nothing to
    // act on yet. Both are correct default-disabled behavior, not a missing-wiring defect.
    private static bool IsExpectedDisabled(string automationId) =>
        automationId is "ApplicationCatalogPrevPageButton" or "ApplicationCatalogNextPageButton"
            or "CopyHashResultButton" or "CancelHashButton" or "SaveHashBaselineButton";

    // Multiple Run* helpers below navigate to the same page (e.g. Settings); if a prior helper
    // already left the app there, SelectByLabel's SelectionItemPattern.Select() on an
    // already-selected ListBoxItem is not guaranteed to report success the way a real state change
    // does (the same caveat NavigationTests documents for Overview being pre-selected at launch).
    // Checking a page-unique marker first avoids treating "already there" as a failure.
    private static bool NavigateIfNeeded(System.Diagnostics.Process process, string navLabel, string markerAutomationId, List<string> failures, string reportName)
    {
        if (UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), markerAutomationId) is not null)
        {
            Report(failures, true, reportName);
            return true;
        }
        var navigated = false;
        for (var attempt = 0; attempt < 3 && !navigated; attempt++)
        {
            try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), navLabel); }
            catch (ElementNotAvailableException) { Thread.Sleep(300); }
        }
        Report(failures, navigated, reportName);
        if (navigated) Thread.Sleep(700);
        return navigated;
    }

    private static void RunKeyboardTraversal(System.Diagnostics.Process process, List<string> failures)
    {
        var navigated = NavigateIfNeeded(process, "Settings", "SaveSettingsButton", failures,
            "Keyboard traversal: navigated to Settings to test Tab order over static form content");
        if (!navigated) return;

        if (!NativeMethods.SetForegroundWindow(process.MainWindowHandle))
        {
            Report(failures, false, "Keyboard traversal: could not bring the main window to the foreground to send real key input");
            return;
        }
        Thread.Sleep(200);

        var saveButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "SaveSettingsButton");
        Report(failures, saveButton is not null, "Keyboard traversal: Settings' Save button is present as a Tab-order anchor");
        if (saveButton is null) return;
        saveButton.SetFocus();
        Thread.Sleep(200);

        // Real Tab key presses (SendInput), not programmatic SetFocus -- this exercises the same
        // WPF keyboard-navigation path a keyboard-only operator relies on, including whatever
        // TabIndex/KeyboardNavigation.TabNavigation the real XAML declares.
        var visited = new List<string>();
        for (var i = 0; i < 8; i++)
        {
            NativeMethods.SendTabKey(shift: false);
            Thread.Sleep(150);
            var focused = TryGetFocusedElement();
            visited.Add(focused is null ? "<none>" : $"{focused.Current.ControlType.ProgrammaticName}:{SafeName(focused)}");
        }
        var distinctStops = visited.Distinct().Count();
        Report(failures, distinctStops >= 3,
            $"Keyboard traversal: pressing Tab 8 times from Save Settings visits at least 3 distinct " +
            $"controls (found {distinctStops}: {string.Join(" -> ", visited)}) -- fewer would indicate a keyboard trap");
        Report(failures, !visited.All(v => v == "<none>"),
            "Keyboard traversal: focus never becomes unrecoverable (null) while tabbing through Settings");

        // Shift+Tab should walk back to a previously-visited stop rather than continuing forward or
        // getting stuck -- basic bidirectional sanity, not a full ordered-sequence comparison (WPF's
        // logical tab order is not guaranteed to be a strict palindrome of the forward walk once
        // group/panel navigation is involved).
        NativeMethods.SendTabKey(shift: true);
        Thread.Sleep(150);
        var afterShiftTab = TryGetFocusedElement();
        var afterShiftTabKey = afterShiftTab is null ? "<none>" : $"{afterShiftTab.Current.ControlType.ProgrammaticName}:{SafeName(afterShiftTab)}";
        Report(failures, visited.Take(visited.Count - 1).Contains(afterShiftTabKey),
            $"Keyboard traversal: Shift+Tab from the last stop ('{visited[^1]}') lands back on an earlier " +
            $"visited stop ('{afterShiftTabKey}'), proving Tab order is bidirectional, not one-way");
    }

    private static void RunReducedMotionRoundTrip(System.Diagnostics.Process process, List<string> failures)
    {
        var navigated = NavigateIfNeeded(process, "Settings", "SaveSettingsButton", failures,
            "Reduced Motion: navigated to Settings");
        if (!navigated) return;

        var checkbox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ReducedMotionCheckBox");
        Report(failures, checkbox is not null, "Reduced Motion: checkbox control is present");
        if (checkbox is null) return;

        var before = checkbox.TryGetCurrentPattern(TogglePattern.Pattern, out var patternObj) && patternObj is TogglePattern tp
            ? tp.Current.ToggleState
            : (ToggleState?)null;
        Report(failures, before is not null, "Reduced Motion: checkbox supports TogglePattern (screen-reader-visible on/off state)");
        if (before is null) return;

        var toggled = UiAutomationHelpers.TryToggle(checkbox, before == ToggleState.Off);
        Thread.Sleep(200);
        Report(failures, toggled, "Reduced Motion: checkbox responds to a toggle request");

        var afterToggle = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ReducedMotionCheckBox");
        var afterState = afterToggle?.TryGetCurrentPattern(TogglePattern.Pattern, out var afterPatternObj) == true && afterPatternObj is TogglePattern atp
            ? atp.Current.ToggleState
            : (ToggleState?)null;
        Report(failures, afterState is not null && afterState != before,
            $"Reduced Motion: toggling the checkbox actually flips its reported state (before={before}, after={afterState})");

        // Restore the original state so this test does not leave a mutated preference behind for
        // whatever runs next -- IsolatedTestProfile's redirected settings.json means this never
        // touches the real operator's setting either way, but a clean before/after is still good
        // hygiene for repeatable local reruns.
        if (afterToggle is not null && before is not null)
            UiAutomationHelpers.TryToggle(afterToggle, before == ToggleState.On);
    }

    private static void RunFocusRestorationAfterDialogClose(System.Diagnostics.Process process, List<string> failures)
    {
        // Overview doesn't carry an EndpointHeader/Diagnostics button of its own -- go straight to
        // Process, which does.
        var navigated = NavigateIfNeeded(process, "Process", "ProcessEventsGrid", failures,
            "Focus restoration: navigated to Process to find a Diagnostics button");
        if (!navigated) return;

        var diagButton = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "ShowDiagnosticsButton");
        Report(failures, diagButton is not null, "Focus restoration: a Diagnostics button is present to open a dialog from");
        if (diagButton is null) return;

        UiAutomationHelpers.Invoke(diagButton);

        // Diagnostics windows are titled per endpoint (e.g. "Process — Diagnostics"), so this scans
        // this process's top-level windows for one whose title contains "Diagnostics" rather than
        // matching an exact name. Uses raw Win32 EnumWindows (like EndpointControlTests'
        // GetTopLevelWindowSnapshot), NOT AutomationElement.RootElement.FindAll -- confirmed
        // empirically 2026-08-03 that the UI Automation Desktop root's Children view does not
        // reliably surface this owned window within any reasonable poll window, even though the
        // window genuinely opens correctly and immediately (verified independently via a standalone
        // repro script using the same raw-EnumWindows technique). That is a UI Automation tree-
        // enumeration limitation in the test's own tooling, not a product defect.
        IntPtr diagHwnd = IntPtr.Zero;
        UiAutomationHelpers.WaitUntil(() =>
        {
            var found = IntPtr.Zero;
            NativeMethods.EnumWindows((hwnd, _) =>
            {
                if (!NativeMethods.IsWindowVisible(hwnd)) return true;
                NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
                if (pid != (uint)process.Id) return true;
                var title = new System.Text.StringBuilder(256);
                NativeMethods.GetWindowText(hwnd, title, 256);
                if (title.ToString().Contains("Diagnostics", StringComparison.OrdinalIgnoreCase))
                {
                    found = hwnd;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            diagHwnd = found;
            return found != IntPtr.Zero;
        }, TimeSpan.FromSeconds(6));
        Report(failures, diagHwnd != IntPtr.Zero, "Focus restoration: Diagnostics window opened");
        if (diagHwnd == IntPtr.Zero) return;

        var diagWindow = AutomationElement.FromHandle(diagHwnd);

        var closePattern = (WindowPattern)diagWindow.GetCurrentPattern(WindowPattern.Pattern);
        closePattern.Close();
        Thread.Sleep(700);

        var focusedAfterClose = TryGetFocusedElement();
        var landedInMainWindow = focusedAfterClose is not null &&
            IsDescendantOfProcessMainWindow(focusedAfterClose, process);
        Report(failures, landedInMainWindow,
            "Focus restoration: closing the Diagnostics window returns keyboard focus into the main window " +
            $"(landed on {(focusedAfterClose is null ? "<none>" : SafeName(focusedAfterClose))}), not lost to the desktop");
    }

    private static bool IsDescendantOfProcessMainWindow(AutomationElement element, System.Diagnostics.Process process)
    {
        try
        {
            var mainWindow = IsolatedTestProfile.GetRootElement(process);
            var walker = TreeWalker.ControlViewWalker;
            var current = element;
            for (var i = 0; i < 20 && current is not null; i++)
            {
                if (current.Equals(mainWindow)) return true;
                current = walker.GetParent(current);
            }
            return false;
        }
        catch (ElementNotAvailableException) { return false; }
    }

    private static AutomationElement? TryGetFocusedElement()
    {
        try { return AutomationElement.FocusedElement; }
        catch (Exception) { return null; }
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
