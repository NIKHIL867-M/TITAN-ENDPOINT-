using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;

namespace TitanEndpoint.App.Accessibility;

/// <summary>FORU.TXT 0.4: "screen-reader announcements for live status changes without flooding
/// the operator." Uses the UIA Notification event (AutomationPeer.RaiseNotificationEvent) rather
/// than a classic bound "live region" TextBlock -- the Notification event reaches Narrator/NVDA/
/// JAWS directly without needing a dedicated always-present, always-empty-until-updated visual
/// element wired into every page, and it is the modern (Windows 10 1809+) API for exactly this.
/// </summary>
public static class LiveRegionAnnouncer
{
    private static Window? _hostWindow;
    private static string? _lastMessage;
    private static DateTime _lastAnnouncedUtc = DateTime.MinValue;

    /// <summary>Same message repeated within this window is treated as noise and dropped -- this
    /// is the "without flooding the operator" half of the requirement (e.g. a polling status line
    /// that hasn't actually changed must not re-announce every tick).</summary>
    private static readonly TimeSpan RepeatSuppressWindow = TimeSpan.FromSeconds(3);

    /// <summary>Call once from MainWindow's Loaded handler -- an AutomationPeer can only be created
    /// for an element that is already part of a live visual tree.</summary>
    public static void Initialize(Window hostWindow) => _hostWindow = hostWindow;

    /// <summary>Polite: waits for the screen reader to finish its current utterance (default -- use
    /// for routine status text). Assertive: interrupts immediately (reserve for rejections/errors/
    /// alerts the operator must not miss).</summary>
    public static void Announce(string message, bool assertive = false)
    {
        if (string.IsNullOrWhiteSpace(message) || _hostWindow is null) return;

        var now = DateTime.UtcNow;
        if (!assertive && message == _lastMessage && now - _lastAnnouncedUtc < RepeatSuppressWindow)
            return;
        _lastMessage = message;
        _lastAnnouncedUtc = now;

        var peer = UIElementAutomationPeer.FromElement(_hostWindow)
                   ?? UIElementAutomationPeer.CreatePeerForElement(_hostWindow);
        peer?.RaiseNotificationEvent(
            AutomationNotificationKind.Other,
            assertive ? AutomationNotificationProcessing.MostRecent : AutomationNotificationProcessing.CurrentThenMostRecent,
            message,
            Guid.NewGuid().ToString());
    }
}
