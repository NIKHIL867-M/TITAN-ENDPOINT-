using System.Linq;
using System.Windows.Automation;

namespace TitanEndpoint.App.UiTests;

/// <summary>Shared UI Automation helpers. Kept deliberately small and dependency-free (no third-
/// party test-automation package) to match this repo's existing convention in
/// GUI\tests\TitanEndpoint.Core.RegressionTests\Program.cs of a plain Check()-based harness rather
/// than an xUnit/NUnit dependency.</summary>
public static class UiAutomationHelpers
{
    public static AutomationElement? FindByAutomationId(AutomationElement root, string automationId)
    {
        var cond = new PropertyCondition(AutomationElement.AutomationIdProperty, automationId);
        return root.FindFirst(TreeScope.Descendants, cond);
    }

    public static AutomationElement? FindByName(AutomationElement root, string name, ControlType? controlType = null)
    {
        Condition cond = new PropertyCondition(AutomationElement.NameProperty, name);
        if (controlType is not null)
            cond = new AndCondition(cond, new PropertyCondition(AutomationElement.ControlTypeProperty, controlType));
        return root.FindFirst(TreeScope.Descendants, cond);
    }

    public static IReadOnlyList<AutomationElement> FindAllByControlType(AutomationElement root, ControlType controlType)
    {
        var cond = new PropertyCondition(AutomationElement.ControlTypeProperty, controlType);
        var found = root.FindAll(TreeScope.Descendants, cond);
        var list = new List<AutomationElement>(found.Count);
        foreach (AutomationElement el in found) list.Add(el);
        return list;
    }

    private static readonly HashSet<string> WindowChromeAutomationIds = new(StringComparer.Ordinal)
        { "Minimize", "Maximize", "Restore", "Close", "System" };

    /// <summary>Same as FindAllByControlType(root, Button) but excludes the OS window-chrome
    /// caption buttons (Minimize/Maximize/Restore/Close). Whether those are exposed as separate
    /// Button automation elements at all depends on the window's current Maximized/Normal state
    /// (found empirically: a Normal-state window exposes 3 more Button elements than the same page
    /// does when Maximized) -- content-button-count assertions must not be sensitive to that.</summary>
    public static IReadOnlyList<AutomationElement> FindContentButtons(AutomationElement root) =>
        FindAllByControlType(root, ControlType.Button)
            .Where(b => !WindowChromeAutomationIds.Contains(b.Current.AutomationId))
            .ToList();

    /// <summary>Nav rail items expose no meaningful default AutomationName from their ListBoxItem
    /// container's ToString() -- select by finding the labelled Text descendant and walking up to
    /// the nearest ancestor that supports SelectionItemPattern, mirroring the exact technique used
    /// (and proven live) during this session's manual verification passes.</summary>
    public static bool SelectByLabel(AutomationElement root, string labelText)
    {
        var textCond = new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text);
        foreach (AutomationElement el in root.FindAll(TreeScope.Descendants, textCond))
        {
            if (el.Current.Name != labelText) continue;

            // The same visible text can also occur in a page heading, table cell, or an
            // off-screen virtualized child. Do not let that non-selectable first match hide
            // the real navigation item farther down the automation tree.
            var walker = TreeWalker.ControlViewWalker;
            var current = el;
            for (var i = 0; i < 10 && current is not null; i++)
            {
                if (current.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var patternObj))
                {
                    ((SelectionItemPattern)patternObj).Select();
                    return true;
                }
                current = walker.GetParent(current);
            }
        }
        return false;
    }

    public static void Invoke(AutomationElement element)
    {
        if (element.TryGetCurrentPattern(InvokePattern.Pattern, out var patternObj))
            ((InvokePattern)patternObj).Invoke();
        else
            throw new InvalidOperationException($"Element '{element.Current.Name}' does not support InvokePattern.");
    }

    public static bool TryToggle(AutomationElement element, bool on)
    {
        if (!element.TryGetCurrentPattern(TogglePattern.Pattern, out var patternObj)) return false;
        var toggle = (TogglePattern)patternObj;
        var current = toggle.Current.ToggleState == ToggleState.On;
        if (current != on) toggle.Toggle();
        return true;
    }

    /// <summary>Polls (rather than a single fixed sleep) until <paramref name="condition"/> returns
    /// true or the timeout elapses. Tolerates ElementNotAvailableException from a mid-navigation
    /// stale reference by retrying rather than propagating. Far more robust against real-machine
    /// timing variance than a fixed Thread.Sleep -- a slow first-run JIT/layout pass no longer
    /// requires guessing a "long enough" constant.</summary>
    public static bool WaitUntil(Func<bool> condition, TimeSpan timeout, TimeSpan? pollInterval = null)
    {
        var interval = pollInterval ?? TimeSpan.FromMilliseconds(200);
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                if (condition()) return true;
            }
            catch (ElementNotAvailableException) { /* transient during a page swap -- keep polling */ }
            Thread.Sleep(interval);
        }
        return false;
    }
}
