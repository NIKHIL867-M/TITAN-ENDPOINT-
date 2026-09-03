using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>FORU.TXT 0.8 "Network suite: test valid/invalid display filters, native capture-filter
/// distinction, packet selection, protocol-tree/hex synchronization, exact field-byte highlight,
/// unsafe/missing PCAP rejection, conversations, Follow Stream directions/gaps/limits, context
/// actions, export, pause view, live refresh stability, and loss state."
///
/// This is a deliberately partial first pass, not the full suite: it verifies the investigation-tab
/// restructuring done this session (Protocol Hierarchy/Top Talkers/Conversations moved out of the
/// permanent sidebar into tabs per FORU.TXT's "move ... out of the cramped permanent sidebar into
/// clear tabs" instruction) actually works -- each tab is selectable and shows its own real,
/// distinguishing control, and non-selected tabs' controls are correctly absent rather than just
/// hidden-but-present -- plus that the display filter box accepts and clears free-text input without
/// destabilizing the page. It does not drive a live packet capture (Network requires elevation and
/// this suite intentionally stays capture-agnostic, checking structure against whatever real,
/// possibly-empty bounded packet view already exists), does not test packet selection -> protocol-
/// tree/hex synchronization (needs at least one real captured packet selected, which needs a live,
/// running capture -- see FullFleetLifecycleTests for that), does not test Follow Stream against a
/// real TCP conversation, and does not test native capture-filter reconfiguration (not yet
/// implemented in the product -- FORU.TXT Part 2 explicitly calls this out as still open: "the
/// current adapter selector is a GUI display filter over retained packets," not native
/// reconfiguration).</summary>
public static class NetworkWorkspaceTests
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
                try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), "Network"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigated, "Navigate to Network page");
            if (!navigated) return failures;
            Thread.Sleep(900);

            RunInvestigationTabs(process, failures);
            RunDisplayFilterRoundTrip(process, failures);
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process);
        }
        return failures;
    }

    private static void RunInvestigationTabs(System.Diagnostics.Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var tabs = UiAutomationHelpers.FindByAutomationId(root, "NetworkInvestigationTabs");
        Report(failures, tabs is not null, "Investigation tabs: NetworkInvestigationTabs control is present");
        if (tabs is null) return;

        // Default tab: Protocol Hierarchy.
        var hierarchyList = UiAutomationHelpers.FindByAutomationId(root, "ProtocolHierarchyList");
        Report(failures, hierarchyList is not null, "Investigation tabs: 'Protocol Hierarchy' is the default-selected tab (its list is present without clicking anything)");
        var exportOnDefaultTab = UiAutomationHelpers.FindByAutomationId(root, "ExportConversationButton");
        Report(failures, exportOnDefaultTab is null, "Investigation tabs: Conversations tab's Export button is correctly ABSENT while Protocol Hierarchy is selected (lazy tab realization, not just hidden)");

        // Top Talkers tab.
        var selectedTopTalkers = SelectTabByHeader(root, "Top Talkers");
        Report(failures, selectedTopTalkers, "Investigation tabs: 'Top Talkers' tab is selectable");
        if (selectedTopTalkers)
        {
            Thread.Sleep(400);
            var rootAfter = IsolatedTestProfile.GetRootElement(process);
            var topTalkersList = UiAutomationHelpers.FindByAutomationId(rootAfter, "TopTalkersList");
            Report(failures, topTalkersList is not null, "Investigation tabs: 'Top Talkers' shows TopTalkersList");
            var hierarchyStillThere = UiAutomationHelpers.FindByAutomationId(rootAfter, "ProtocolHierarchyList");
            Report(failures, hierarchyStillThere is null, "Investigation tabs: Protocol Hierarchy's list is correctly ABSENT once Top Talkers is selected");
        }

        // Conversations tab.
        var selectedConversations = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Conversations");
        Report(failures, selectedConversations, "Investigation tabs: 'Conversations' tab is selectable");
        if (selectedConversations)
        {
            Thread.Sleep(400);
            var rootAfter = IsolatedTestProfile.GetRootElement(process);
            Report(failures, UiAutomationHelpers.FindByAutomationId(rootAfter, "ConversationsGrid") is not null,
                "Investigation tabs: 'Conversations' shows ConversationsGrid");
            Report(failures, UiAutomationHelpers.FindByAutomationId(rootAfter, "ExportConversationButton") is not null,
                "Investigation tabs: 'Conversations' shows the Export button");
            Report(failures, UiAutomationHelpers.FindByAutomationId(rootAfter, "FollowStreamTextBox") is not null,
                "Investigation tabs: 'Conversations' shows the Follow Stream text pane");
            Report(failures, UiAutomationHelpers.FindByAutomationId(rootAfter, "FollowTcpStreamButton") is not null,
                "Investigation tabs: 'Conversations' exposes the dedicated Follow TCP Stream window action");
        }

        // Return to Protocol Hierarchy so RunDisplayFilterRoundTrip starts from a known state.
        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Protocol Hierarchy");
        Thread.Sleep(300);
    }

    private static void RunDisplayFilterRoundTrip(System.Diagnostics.Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        Report(failures, UiAutomationHelpers.FindByAutomationId(root, "NetworkCaptureStateText") is not null,
            "Capture workspace: real capture state is surfaced");
        var selectedPacketBytes = SelectTabByHeader(root, "Packet Bytes");
        Report(failures, selectedPacketBytes, "Packet workspace: 'Packet Bytes' tab is selectable");
        if (selectedPacketBytes)
        {
            Thread.Sleep(250);
            Report(failures, UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "PacketBytesLines") is not null,
                "Packet workspace: bounded hexadecimal/ASCII byte pane is realized");
        }
        var filterBox = UiAutomationHelpers.FindByAutomationId(root, "NetworkDisplayFilterTextBox");
        Report(failures, filterBox is not null, "Display filter: filter text box is present");
        if (filterBox is null) return;

        if (!filterBox.TryGetCurrentPattern(ValuePattern.Pattern, out var patternObj))
        {
            Report(failures, false, "Display filter: text box supports ValuePattern (needed to set text programmatically)");
            return;
        }
        var valuePattern = (ValuePattern)patternObj;

        // A syntactically nonsense filter must not crash the page or throw -- it should just be
        // treated as a plain-text search (FORU.TXT: "Display filters support plain search and
        // protocol:, ip:, port:, process:, adapter:, and direction:") that most likely matches
        // nothing, not an unhandled exception.
        valuePattern.SetValue("this:is:not:a:real:filter:syntax###");
        Thread.Sleep(400);
        var stillThereAfterInvalid = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "NetworkPacketGrid");
        Report(failures, stillThereAfterInvalid is not null,
            "Display filter: an invalid/nonsense filter string does not crash the page (packet grid still present)");

        valuePattern.SetValue("");
        Thread.Sleep(300);
        var clearedFilterBox = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "NetworkDisplayFilterTextBox");
        var clearedOk = clearedFilterBox is not null && clearedFilterBox.TryGetCurrentPattern(ValuePattern.Pattern, out var afterPatternObj)
            && string.IsNullOrEmpty(((ValuePattern)afterPatternObj).Current.Value);
        Report(failures, clearedOk, "Display filter: clearing the filter text box actually empties it");
    }

    /// <summary>Same technique as CustomRuleWorkflowTests.SelectTabByHeader -- TabItem's default UI
    /// Automation Name mirrors its Header content, so this selects directly by ControlType.TabItem +
    /// Name rather than the nav-rail's find-Text-then-walk-up-to-SelectionItem technique.</summary>
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
