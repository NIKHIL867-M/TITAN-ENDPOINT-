using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace TitanEndpoint.App.Views;

public partial class CorrelationGraphView : UserControl
{
    public CorrelationGraphView()
    {
        InitializeComponent();
        Loaded += (_, _) => PlayEntranceFade();
    }

    /// <summary>Whole pentagon (nodes + whatever edges already exist) fades in once when the page is
    /// first opened. Each edge added later fades in again on its own (FlowEdgeControl) -- the two
    /// compose harmlessly since both start from full-transparent. Duration read fresh from
    /// "MotionDuration" at animation-start time, same Reduced-Motion-safe convention as RadialGauge
    /// and FlowEdgeControl -- see App.xaml.cs's ApplyReducedMotion doc comment for why a
    /// Storyboard-embedded DynamicResource is not used here instead.</summary>
    private void PlayEntranceFade()
    {
        var duration = (Duration)(GraphCanvasRoot.TryFindResource("MotionDuration") ?? new Duration(TimeSpan.FromSeconds(0.14)));
        if (duration.TimeSpan == TimeSpan.Zero) { GraphCanvasRoot.Opacity = 1; return; }
        GraphCanvasRoot.Opacity = 0;
        GraphCanvasRoot.BeginAnimation(UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } });
    }
}
