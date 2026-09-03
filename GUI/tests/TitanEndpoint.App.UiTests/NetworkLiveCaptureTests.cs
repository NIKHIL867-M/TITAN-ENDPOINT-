using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Windows.Automation;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>Live, elevation-required end-to-end pass over every real control on the Network page.
/// Actually starts the real Network endpoint (titan.exe / Npcap), generates real outbound traffic so
/// the capture is genuinely non-empty, then drives capture stats, adapter/display-filter round trips
/// against real packets, packet selection -> protocol-tree/raw-JSON/hex-ASCII synchronization, the
/// three investigation tabs (Protocol Hierarchy/Top Talkers/Conversations) against real data, and the
/// Follow TCP Stream window against a real conversation.
///
/// This is the live counterpart to NetworkWorkspaceTests (which deliberately stays capture-agnostic
/// and says so in its own doc comment) and goes deeper than FullFleetLifecycleTests' Network case
/// (which only proves process start/stop, not any packet-level feature).
///
/// Skips entirely (not a failure) if the launched GUI process is not elevated, matching this
/// project's "keep elevated live tests out of ordinary CI" boundary -- see EndpointControlTests and
/// FullFleetLifecycleTests' doc comments for the same principle applied elsewhere.
///
/// Deliberately does not invoke Export, Follow Stream's own Save, or Open Raw Capture Folder -- the
/// first two open a native modal Save dialog and the third spawns Explorer, none of which this
/// Console-harness-based project automates (see UiAutomationHelpers' doc comment: "no third-party
/// test-automation package"). Their enabled/CanExecute state is checked instead where meaningful.</summary>
public static class NetworkLiveCaptureTests
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
            if (!FullFleetLifecycleTests.IsProcessElevated(process.Id))
            {
                Console.WriteLine("[SKIP] NetworkLiveCaptureTests: requires an elevated GUI process " +
                    "(Network capture needs Npcap/Administrator); this run is not elevated.");
                return failures;
            }

            var navigated = false;
            for (var attempt = 0; attempt < 3 && !navigated; attempt++)
            {
                try { navigated = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), "Network"); }
                catch (ElementNotAvailableException) { Thread.Sleep(300); }
            }
            Report(failures, navigated, "Navigate to Network page");
            if (!navigated) return failures;
            Thread.Sleep(700);

            var root = IsolatedTestProfile.GetRootElement(process);
            var startBtn = UiAutomationHelpers.FindByAutomationId(root, "StartStopEndpointButton");
            Report(failures, startBtn is not null && startBtn.Current.Name.Contains("START ENDPOINT"),
                "Network: START ENDPOINT button present before start");
            if (startBtn is null) return failures;

            var alreadyRunning = Process.GetProcessesByName("titan").Length > 0;
            Report(failures, !alreadyRunning, "Network: titan.exe is not already running before this case (clean start)");

            UiAutomationHelpers.Invoke(startBtn);
            var started = UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName("titan").Length > 0, TimeSpan.FromSeconds(20));
            Report(failures, started, "Network: titan.exe is running after Start");
            if (!started) return failures;

            var stopReady = UiAutomationHelpers.WaitUntil(() =>
            {
                var btn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
                return btn is not null && btn.Current.Name.Contains("STOP ENDPOINT") && btn.Current.IsEnabled;
            }, TimeSpan.FromSeconds(8));
            Report(failures, stopReady, "Network: STOP ENDPOINT button becomes enabled after Start");

            var liveText = UiAutomationHelpers.WaitUntil(() =>
            {
                var el = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "NetworkCaptureStateText");
                return el is not null && el.Current.Name.Contains("LIVE");
            }, TimeSpan.FromSeconds(15));
            Report(failures, liveText, "Capture toolbar: capture status flips to LIVE once real native health arrives");

            // Generate real outbound traffic in the background rather than relying solely on
            // incidental OS chatter -- even if HTTP itself fails offline, the DNS lookup attempts
            // alone still produce real captured UDP packets.
            trafficTask = GenerateTrafficAsync(trafficCts.Token);

            var gotPackets = UiAutomationHelpers.WaitUntil(
                () => CountDescendants(IsolatedTestProfile.GetRootElement(process), "NetworkPacketGrid", ControlType.DataItem) > 0,
                TimeSpan.FromSeconds(45));
            Report(failures, gotPackets, "Packet list: real captured packets appear after Start + generated traffic");

            if (gotPackets)
            {
                Thread.Sleep(2000); // let a few more real packets accumulate before the filter round-trip
                RunPacketSelectionChecks(process, failures);
                RunDisplayFilterLiveRoundTrip(process, failures);
                RunAdapterDropdownCheck(process, failures);
                RunInvestigationTabsLiveChecks(process, failures);
                RunFollowStreamLiveWindow(process, failures);
            }

            trafficCts.Cancel();

            var stopReadyAtTeardown = UiAutomationHelpers.WaitUntil(() =>
            {
                var button = UiAutomationHelpers.FindByAutomationId(
                    IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
                return button is not null && button.Current.IsEnabled && button.Current.Name.Contains("STOP ENDPOINT");
            }, TimeSpan.FromSeconds(8));
            var freshStop = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "StartStopEndpointButton");
            if (stopReadyAtTeardown && freshStop is not null)
            {
                UiAutomationHelpers.Invoke(freshStop);
                var exited = UiAutomationHelpers.WaitUntil(() => Process.GetProcessesByName("titan").Length == 0, TimeSpan.FromSeconds(15));
                Report(failures, exited, "Network: titan.exe exited after Stop");
            }
            else
            {
                Report(failures, false, "Network: STOP ENDPOINT still findable/enabled at teardown");
            }
        }
        finally
        {
            trafficCts.Cancel();
            try { trafficTask?.Wait(TimeSpan.FromSeconds(3)); } catch { /* best effort */ }
            IsolatedTestProfile.CloseAndWait(process);
            foreach (var p in Process.GetProcessesByName("titan")) { try { p.Kill(); } catch { /* best effort */ } }
        }
        return failures;
    }

    private static void RunPacketSelectionChecks(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        // The packet grid has no sort applied (display order == capture/insertion order), so the
        // LAST realized row is the most recently captured packet -- selecting the first (oldest)
        // risks a real, honest "expired under bounded raw-capture retention" result if enough time
        // has passed since it was captured, which is a distinct case from a genuine mapping defect.
        var selected = SelectLastItem(root, "NetworkPacketGrid", ControlType.DataItem);
        Report(failures, selected, "Packet list: a real captured packet row can be selected");
        if (!selected) return;
        Thread.Sleep(700); // protocol tree rebuild + async raw-PCAP byte load

        var treeItems = CountDescendants(IsolatedTestProfile.GetRootElement(process), "ProtocolDetailsTree", ControlType.TreeItem);
        Report(failures, treeItems > 0, $"Protocol tree: real protocol fields render for the selected packet (found {treeItems})");

        // Clicking a tree node exercises NetworkView.ProtocolTree_SelectedItemChanged ->
        // NetworkViewModel.SelectProtocolField -> PacketBytesViewModel.HighlightFieldRange. Best
        // effort: not every node carries a FieldKey, so only require that it doesn't destabilize
        // the page, not that a highlight always results.
        var treeNodeClicked = SelectFirstItem(IsolatedTestProfile.GetRootElement(process), "ProtocolDetailsTree", ControlType.TreeItem);
        Report(failures, treeNodeClicked, "Protocol tree: a field node can be selected without crashing the page");

        // PacketBytesViewModel.Lines is populated only by LoadBytes() on a genuine, hash/offset-
        // validated raw-PCAP read; ShowValidationError() (the failure path) always leaves it empty
        // -- see PacketBytesViewModel.cs. A non-zero rendered row count is therefore direct proof
        // the exact byte-range mapping to the real .pcap segment on disk actually worked, not just
        // that the JSON record existed.
        var switchedToBytes = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Packet Bytes");
        Report(failures, switchedToBytes, "Raw Capture pane: 'Packet Bytes' sub-tab is selectable");
        if (switchedToBytes)
        {
            var gotBytes = UiAutomationHelpers.WaitUntil(() =>
                CountDescendants(IsolatedTestProfile.GetRootElement(process), "PacketBytesLines", ControlType.Text) > 0,
                TimeSpan.FromSeconds(10));
            Report(failures, gotBytes, "Packet Bytes: real offset/hex/ASCII rows are rendered from the exact retained raw-PCAP segment");
            if (!gotBytes)
            {
                var msg = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "NetworkBytesPaneMessage");
                Console.WriteLine($"[INFO] Diagnostic -- NetworkViewModel.BytesPaneMessage was: \"{msg?.Current.Name}\"");
            }

            if (gotBytes)
            {
                var copyRoot = IsolatedTestProfile.GetRootElement(process);
                foreach (var (label, name) in new[] { ("Copy hex", "hex"), ("Copy escaped", "escaped"), ("Copy text", "text") })
                {
                    var btn = UiAutomationHelpers.FindByName(copyRoot, label, ControlType.Button);
                    var ok = btn is not null && btn.Current.IsEnabled;
                    if (ok) UiAutomationHelpers.Invoke(btn!);
                    Report(failures, ok, $"Packet Bytes: '{label}' is enabled and invocable for a real loaded packet");
                }
            }
        }

        var switchedToRawJson = SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Raw JSON");
        Report(failures, switchedToRawJson, "Raw Capture pane: 'Raw JSON' sub-tab is selectable");

        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Segments");
    }

    private static void RunDisplayFilterLiveRoundTrip(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var filterBox = UiAutomationHelpers.FindByAutomationId(root, "NetworkDisplayFilterTextBox");
        var applyBtn = UiAutomationHelpers.FindByAutomationId(root, "ApplyNetworkDisplayFilterButton");
        var clearBtn = UiAutomationHelpers.FindByAutomationId(root, "ClearNetworkDisplayFilterButton");
        var saveBtn = UiAutomationHelpers.FindByAutomationId(root, "SaveNetworkDisplayFilterButton");
        if (filterBox is null || applyBtn is null || clearBtn is null || saveBtn is null ||
            !filterBox.TryGetCurrentPattern(ValuePattern.Pattern, out var patternObj))
        {
            Report(failures, false, "Display filter: filter box, Apply, Clear, and Save controls are all present");
            return;
        }
        var valuePattern = (ValuePattern)patternObj;
        var beforeCount = CountDescendants(root, "NetworkPacketGrid", ControlType.DataItem);

        var noMatchToken = "titan-live-test-no-match-" + Guid.NewGuid().ToString("N")[..8];
        valuePattern.SetValue(noMatchToken);
        Thread.Sleep(300);
        UiAutomationHelpers.Invoke(applyBtn);
        Thread.Sleep(700);
        var filteredCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "NetworkPacketGrid", ControlType.DataItem);
        Report(failures, filteredCount == 0,
            $"Display filter: an unmatched real filter genuinely empties the packet grid (before={beforeCount}, after={filteredCount})");

        var saveEnabled = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "SaveNetworkDisplayFilterButton");
        Report(failures, saveEnabled is not null && saveEnabled.Current.IsEnabled, "Display filter: Save filter is enabled for non-empty filter text");
        if (saveEnabled is not null && saveEnabled.Current.IsEnabled) UiAutomationHelpers.Invoke(saveEnabled);

        UiAutomationHelpers.Invoke(clearBtn);
        Thread.Sleep(700);
        var restoredCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "NetworkPacketGrid", ControlType.DataItem);
        Report(failures, restoredCount > 0, $"Display filter: Clear genuinely restores the packet grid (restored={restoredCount})");
    }

    private static void RunAdapterDropdownCheck(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var combo = UiAutomationHelpers.FindByAutomationId(root, "NetworkAdapterComboBox");
        Report(failures, combo is not null, "Adapter filter: adapter combo box is present");
        if (combo is null || !combo.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var patternObj))
        {
            Report(failures, false, "Adapter filter: combo box supports ExpandCollapsePattern");
            return;
        }
        var expand = (ExpandCollapsePattern)patternObj;
        try
        {
            expand.Expand();
            Thread.Sleep(300);
            var items = combo.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
            Report(failures, items.Count >= 1,
                $"Adapter filter: real capture produced at least the default adapter entry (found {items.Count})");
        }
        finally { expand.Collapse(); }
    }

    private static void RunInvestigationTabsLiveChecks(Process process, List<string> failures)
    {
        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Protocol Hierarchy");
        Thread.Sleep(400);
        var hierarchyPopulated = CountDescendants(IsolatedTestProfile.GetRootElement(process), "ProtocolHierarchyList", ControlType.Text) > 0;
        Report(failures, hierarchyPopulated, "Protocol Hierarchy: real captured-protocol counts render");

        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Top Talkers");
        Thread.Sleep(400);
        var talkersPopulated = CountDescendants(IsolatedTestProfile.GetRootElement(process), "TopTalkersList", ControlType.Text) > 0;
        Report(failures, talkersPopulated, "Top Talkers: real remote-endpoint byte totals render");

        SelectTabByHeader(IsolatedTestProfile.GetRootElement(process), "Conversations");
        Thread.Sleep(400);
        var convCount = CountDescendants(IsolatedTestProfile.GetRootElement(process), "ConversationsGrid", ControlType.DataItem);
        Report(failures, convCount > 0, $"Conversations: real conversations are grouped from captured packets (found {convCount})");
    }

    private static void RunFollowStreamLiveWindow(Process process, List<string> failures)
    {
        var root = IsolatedTestProfile.GetRootElement(process);
        var selectedConv = SelectFirstFollowableConversation(root);
        Report(failures, selectedConv, "Conversations: a real TCP conversation row can be selected");
        if (!selectedConv) return;
        Thread.Sleep(300);

        var followBtn = UiAutomationHelpers.FindByAutomationId(IsolatedTestProfile.GetRootElement(process), "FollowTcpStreamButton");
        Report(failures, followBtn is not null && followBtn.Current.IsEnabled,
            "Conversations: Follow TCP Stream button is enabled once a conversation is selected");
        if (followBtn is null || !followBtn.Current.IsEnabled) return;
        UiAutomationHelpers.Invoke(followBtn);

        // Locate the new window by real HWND (same technique as EndpointControlTests' Diagnostics
        // window: AutomationElement.FromHandle) rather than AutomationElement.RootElement.FindFirst
        // by AutomationId -- found empirically to be far more reliable for a just-created top-level
        // window than a full Desktop-scoped Control-view search.
        IntPtr streamHandle = IntPtr.Zero;
        var opened = UiAutomationHelpers.WaitUntil(() =>
        {
            foreach (var (handle, title) in GetProcessWindows(process.Id))
            {
                if (!title.StartsWith("Follow Stream", StringComparison.Ordinal)) continue;
                streamHandle = handle;
                return true;
            }
            return false;
        }, TimeSpan.FromSeconds(10));
        Report(failures, opened, "Follow TCP Stream: focused window opens for a real conversation");
        if (!opened) return;
        var window = AutomationElement.FromHandle(streamHandle);
        // WPF's TextBoxAutomationPeer.SetValue() throws ElementNotEnabledException if the
        // containing window isn't the OS foreground window -- IsEnabled is true regardless, so this
        // is purely a focus precondition, not a product state. AutomationElement.SetFocus() alone
        // was not sufficient (found empirically); NativeMethods.SetForegroundWindow (already used
        // elsewhere in this namespace) is the real OS-level activation WPF's focus check needs.
        NativeMethods.SetForegroundWindow(streamHandle);
        Thread.Sleep(200);

        try
        {
            var loaded = UiAutomationHelpers.WaitUntil(() =>
            {
                var box = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamContentTextBox");
                return box is not null && box.TryGetCurrentPattern(ValuePattern.Pattern, out var vp) &&
                       ((ValuePattern)vp).Current.Value.Length > 0;
            }, TimeSpan.FromSeconds(15));
            Report(failures, loaded, "Follow TCP Stream: real stream content is reconstructed from the retained conversation");

            foreach (var (id, label) in new[]
            {
                ("FollowStreamHexModeRadio", "Hex"), ("FollowStreamAsciiModeRadio", "ASCII"),
                ("FollowStreamRawModeRadio", "Raw"), ("FollowStreamTextModeRadio", "Text")
            })
            {
                var radio = UiAutomationHelpers.FindByAutomationId(window, id);
                object? selPatternObj = null;
                var toggled = radio is not null && radio.TryGetCurrentPattern(SelectionItemPattern.Pattern, out selPatternObj);
                if (toggled) ((SelectionItemPattern)selPatternObj!).Select();
                Report(failures, toggled, $"Follow TCP Stream: '{label}' view mode is selectable without crashing the window");
                Thread.Sleep(150);
            }

            var directionCombo = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamDirectionCombo");
            Report(failures, directionCombo is not null, "Follow TCP Stream: direction filter combo is present");

            var searchBox = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamSearchBox");
            if (searchBox is not null && searchBox.TryGetCurrentPattern(ValuePattern.Pattern, out var searchPatternObj))
            {
                ((ValuePattern)searchPatternObj).SetValue("e");
                Thread.Sleep(150); // let CommandManager requery SearchNextCommand now SearchTerm is non-empty
                var nextBtn = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamSearchNextButton");
                Report(failures, nextBtn is not null && nextBtn.Current.IsEnabled,
                    "Follow TCP Stream: Search Next becomes enabled once a search term is entered");
                if (nextBtn is not null && nextBtn.Current.IsEnabled) UiAutomationHelpers.Invoke(nextBtn);
                Thread.Sleep(200);
                var stillOpen = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamStatusText") is not null;
                Report(failures, stillOpen, "Follow TCP Stream: search next does not crash the window");
            }

            var copyBtn = UiAutomationHelpers.FindByAutomationId(window, "FollowStreamCopyButton");
            Report(failures, copyBtn is not null && copyBtn.Current.IsEnabled, "Follow TCP Stream: Copy is enabled for a real reconstructed stream");
            if (copyBtn is not null && copyBtn.Current.IsEnabled) UiAutomationHelpers.Invoke(copyBtn);
        }
        finally
        {
            if (window.TryGetCurrentPattern(WindowPattern.Pattern, out var winPatternObj))
            { try { ((WindowPattern)winPatternObj).Close(); } catch { /* best effort */ } }
        }
    }

    /// <summary>Real outbound HTTP/DNS traffic so the live capture has genuine, non-incidental
    /// packets to observe. Runs until cancelled; failures (e.g. offline machine) are swallowed
    /// because even a failed connection attempt's DNS lookup is itself real captured traffic.</summary>
    private static Task GenerateTrafficAsync(CancellationToken ct) => Task.Run(() =>
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var urls = new[] { "http://example.com/", "https://example.com/", "https://www.microsoft.com/" };
        var i = 0;
        while (!ct.IsCancellationRequested)
        {
            try { client.GetAsync(urls[i % urls.Length], ct).GetAwaiter().GetResult(); }
            catch { /* best effort -- see doc comment */ }
            i++;
            Thread.Sleep(1500);
        }
    }, ct);

    /// <summary>Reuses NativeMethods (EnumWindows/IsWindowVisible/GetWindowText/GetWindowThreadProcessId),
    /// already defined internal in EndpointControlTests.cs in this same namespace -- returns real
    /// HWNDs so a just-opened window can be resolved via AutomationElement.FromHandle, which was
    /// found empirically to be far more reliable than a Desktop-scoped AutomationId search for a
    /// window that only just appeared.</summary>
    private static List<(IntPtr Handle, string Title)> GetProcessWindows(int pid)
    {
        var windows = new List<(IntPtr, string)>();
        NativeMethods.EnumWindows((hwnd, _) =>
        {
            if (!NativeMethods.IsWindowVisible(hwnd)) return true;
            NativeMethods.GetWindowThreadProcessId(hwnd, out var windowPid);
            if (windowPid != (uint)pid) return true;
            var title = new System.Text.StringBuilder(256);
            NativeMethods.GetWindowText(hwnd, title, 256);
            var text = title.ToString();
            if (!string.IsNullOrEmpty(text)) windows.Add((hwnd, text));
            return true;
        }, IntPtr.Zero);
        return windows;
    }

    private static int CountDescendants(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return -1;
        return container.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType)).Count;
    }

    private static bool SelectFirstItem(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return false;
        var item = container.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType));
        if (item is null || !item.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var p)) return false;
        ((SelectionItemPattern)p).Select();
        return true;
    }

    private static bool SelectFirstFollowableConversation(AutomationElement root)
    {
        var grid = UiAutomationHelpers.FindByAutomationId(root, "ConversationsGrid");
        if (grid is null) return false;
        for (var page = 0; page < 20; page++)
        {
            var items = grid.FindAll(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem));
            foreach (AutomationElement item in items)
            {
                var cells = item.FindAll(TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text));
                var isTcp = false;
                foreach (AutomationElement cell in cells)
                {
                    if (string.Equals(cell.Current.Name, "TCP", StringComparison.OrdinalIgnoreCase))
                    { isTcp = true; break; }
                }
                if (!isTcp) continue;
                if (!item.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var selection)) continue;
                ((SelectionItemPattern)selection).Select();
                Thread.Sleep(150);
                var follow = UiAutomationHelpers.FindByAutomationId(root, "FollowTcpStreamButton");
                if (follow is not null && follow.Current.IsEnabled) return true;
            }

            // Conversations is virtualized. Under a busy full-suite run the first
            // realized viewport can contain only UDP/ARP/ICMP rows even though real
            // TCP conversations exist farther down. Page through realized rows
            // rather than treating the current viewport as the whole collection.
            if (!grid.TryGetCurrentPattern(ScrollPattern.Pattern, out var scrollObject)) break;
            var scroll = (ScrollPattern)scrollObject;
            if (!scroll.Current.VerticallyScrollable || scroll.Current.VerticalScrollPercent >= 100) break;
            try { scroll.ScrollVertical(ScrollAmount.LargeIncrement); }
            catch (InvalidOperationException) { break; }
            Thread.Sleep(200);
        }
        return false;
    }

    /// <summary>Scrolls the container to its end (if scrollable) before picking the last realized
    /// item -- WPF virtualizes DataGrid rows, so without scrolling, "last" would just mean the last
    /// row currently on screen from the top of an unscrolled view, not the true most-recent item.</summary>
    private static bool SelectLastItem(AutomationElement root, string automationId, ControlType controlType)
    {
        var container = UiAutomationHelpers.FindByAutomationId(root, automationId);
        if (container is null) return false;
        if (container.TryGetCurrentPattern(ScrollPattern.Pattern, out var scrollPatternObj))
        {
            try
            {
                var scroll = (ScrollPattern)scrollPatternObj;
                if (scroll.Current.VerticallyScrollable) scroll.SetScrollPercent(ScrollPattern.NoScroll, 100);
            }
            catch { /* best effort -- not every grid state supports scrolling at this instant */ }
        }
        var items = container.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType));
        if (items.Count == 0) return false;
        var last = items[items.Count - 1];
        if (!last.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var p)) return false;
        ((SelectionItemPattern)p).Select();
        return true;
    }

    /// <summary>Same technique as NetworkWorkspaceTests/CustomRuleWorkflowTests.SelectTabByHeader --
    /// TabItem's default UI Automation Name mirrors its Header content. Duplicated locally rather
    /// than shared, matching this file's existing convention of small self-contained test files.</summary>
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
