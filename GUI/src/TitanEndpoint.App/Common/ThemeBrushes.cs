using System.Windows;
using System.Windows.Media;
using TitanEndpoint.Core.Health;

namespace TitanEndpoint.App.Common;

/// <summary>Central lookup so ViewModels can compute a status Brush without XAML converters.</summary>
public static class ThemeBrushes
{
    public static Brush Get(string key) => (Brush)Application.Current.Resources[key];

    public static Brush Healthy => Get("HealthyBrush");
    public static Brush Warning => Get("WarningBrush");
    public static Brush Critical => Get("CriticalBrush");
    public static Brush Disabled => Get("TextDisabledBrush");
    public static Brush Secondary => Get("TextSecondaryBrush");
    public static Brush Accent => Get("AccentBrush");

    public static Brush ForHealth(HealthStatus status) => status switch
    {
        HealthStatus.Healthy => Healthy,
        HealthStatus.Degraded => Warning,
        HealthStatus.Failed => Critical,
        _ => Disabled
    };

    /// <summary>Nav-rail / overview dot: grey stopped, green active, amber degraded, red failed.</summary>
    public static Brush ForEndpointDot(bool isRunning, HealthStatus health) =>
        !isRunning ? Disabled : ForHealth(health == HealthStatus.Unknown ? HealthStatus.Healthy : health);
}
