using System.Windows;
using System.Windows.Media;

namespace TitanEndpoint.App.Accessibility;

/// <summary>FORU.TXT 0.4 "ACCESSIBILITY COMPLETION REQUIREMENTS": a real Windows High Contrast
/// resource path using SystemColors, reacting while the app is running -- the prior static audit
/// found no HighContrast/SystemColors handling anywhere in this project.
///
/// Follows the same "swap which resource a shared key points to" pattern already proven this
/// session for ToggleSwitchStyle/MotionDuration (see Theme.xaml's comment on why a
/// DynamicResource-inside-a-Storyboard is unsafe -- this is the same safe alternative, applied to
/// plain brush resources instead): every consumer already binds Background/Foreground/BorderBrush
/// via StaticResource to the *named* brush keys below (WindowBgBrush, TextPrimaryBrush, etc.), so
/// overwriting Application.Resources[key] with a SystemColors brush and calling
/// FrameworkElement.InvalidateVisual/UpdateLayout is not required -- WPF's StaticResource lookup at
/// XAML-parse time already resolved to the SAME ResourceDictionary Brush object slot; replacing the
/// dictionary ENTRY does not retroactively re-resolve already-parsed StaticResource bindings.
/// Because of that, every Brush key below is instead swapped to a *mutable* SolidColorBrush whose
/// Color is updated in place (Color is a struct property on SolidColorBrush, and changing it does
/// propagate to every already-resolved consumer, exactly like the DiscoveredStatus brushes this
/// app already animates) -- see Apply() for the concrete mechanism.
///
/// Status colors (Healthy/Warning/Critical) are intentionally left untouched under High Contrast:
/// they are already highly saturated, and FORU.TXT is explicit that "colour alone is never the
/// only indication" -- every status already carries text/icon meaning alongside the color, so the
/// brand status palette remains meaningful and distinguishable without being forced through the
/// OS's (much smaller) high-contrast color set.
/// </summary>
public static class HighContrastThemeManager
{
    private static bool _initialized;
    private static readonly string[] StructuralBrushKeys =
    {
        "WindowBgBrush", "NavBgBrush", "PanelBgBrush", "PanelBg2Brush", "BorderBrush2",
        "TextPrimaryBrush", "TextSecondaryBrush", "TextDisabledBrush", "AccentBrush", "AccentBrushSoft"
    };

    private static readonly Dictionary<string, Color> _originalColors = new();
    private static readonly Dictionary<string, Color> _highContrastColors = new()
    {
        ["WindowBgBrush"] = SystemColors.WindowColor,
        ["NavBgBrush"] = SystemColors.ControlColor,
        ["PanelBgBrush"] = SystemColors.WindowColor,
        ["PanelBg2Brush"] = SystemColors.ControlColor,
        ["BorderBrush2"] = SystemColors.WindowFrameColor,
        ["TextPrimaryBrush"] = SystemColors.WindowTextColor,
        ["TextSecondaryBrush"] = SystemColors.WindowTextColor,
        ["TextDisabledBrush"] = SystemColors.GrayTextColor,
        ["AccentBrush"] = SystemColors.HighlightColor,
        ["AccentBrushSoft"] = SystemColors.HighlightColor,
    };

    public static bool IsActive => SystemParameters.HighContrast;

    /// <summary>Call once, after Application.Resources is populated (Theme.xaml merged) and BEFORE
    /// the first window/UserControl is constructed -- App.xaml.cs.OnStartup, immediately after
    /// ApplyReducedMotion. Must run this early: any StaticResource consumer resolves to whichever
    /// Brush OBJECT sits in the dictionary slot at the moment it is parsed, so an unfreeze-and-clone
    /// done here (before anything else is built) is what lets every later Color mutation actually
    /// reach every consumer -- replacing the slot's Brush object AFTER windows already exist would
    /// silently strand any StaticResource-bound consumer on the old, now-disconnected instance.</summary>
    public static void Initialize()
    {
        if (_initialized) return;
        _initialized = true;

        var resources = Application.Current.Resources;
        foreach (var key in StructuralBrushKeys)
        {
            if (resources[key] is not SolidColorBrush brush) continue;
            if (brush.IsFrozen)
            {
                brush = brush.Clone();
                resources[key] = brush;
            }
            _originalColors[key] = brush.Color;
        }

        SystemParameters.StaticPropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SystemParameters.HighContrast)) Apply();
        };
        Apply();
    }

    private static void Apply()
    {
        var resources = Application.Current.Resources;
        var active = SystemParameters.HighContrast;

        foreach (var key in StructuralBrushKeys)
        {
            if (resources[key] is not SolidColorBrush brush || brush.IsFrozen) continue;
            var target = active && _highContrastColors.TryGetValue(key, out var hc)
                ? hc
                : _originalColors.TryGetValue(key, out var orig) ? orig : brush.Color;
            if (brush.Color != target) brush.Color = target;
        }
    }
}
