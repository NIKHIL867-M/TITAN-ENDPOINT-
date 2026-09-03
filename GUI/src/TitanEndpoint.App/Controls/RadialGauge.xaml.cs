using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace TitanEndpoint.App.Controls;

/// <summary>Circular progress gauge -- FORU.TXT GUI-upgrade ask for a "circle graph" in the Overview
/// Resource Usage panel, real disk-budget-used percentage rather than a decorative shape. The arc
/// color follows the same reserved-status convention as the rest of the app (Theme.xaml: green only
/// for healthy, amber only for pending/degraded, red only for rejected/failed/critical) -- crossing
/// the disk budget is a genuine operational state, not decoration, so it is allowed to use those
/// brushes here.
///
/// Santosh, 2026-08-04: "I need animated graph" for the Overview RAM readout -- the arc now animates
/// smoothly from its previous value to each new one instead of snapping, via a private
/// AnimatedFraction DP driven by a DoubleAnimation off the real Percentage value. Duration comes from
/// the app-wide "MotionDuration" resource (Theme.xaml/App.xaml.cs.ApplyReducedMotion), so Reduced
/// Motion correctly collapses this to an instant jump like every other animation in this app, rather
/// than needing its own separate a11y wiring.</summary>
public partial class RadialGauge : UserControl
{
    public static readonly DependencyProperty PercentageProperty = DependencyProperty.Register(
        nameof(Percentage), typeof(double), typeof(RadialGauge), new PropertyMetadata(0.0, OnPercentageChanged));

    public static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(
        nameof(Caption), typeof(string), typeof(RadialGauge), new PropertyMetadata("", OnVisualPropertyChanged));

    private static readonly DependencyProperty AnimatedFractionProperty = DependencyProperty.Register(
        nameof(AnimatedFraction), typeof(double), typeof(RadialGauge), new PropertyMetadata(0.0, OnVisualPropertyChanged));

    /// <summary>0.0-1.0. Values above 1.0 are clamped for drawing (an over-budget state is still
    /// shown as a full ring plus the real percentage text, e.g. "134%", not an impossible arc.</summary>
    public double Percentage
    {
        get => (double)GetValue(PercentageProperty);
        set => SetValue(PercentageProperty, value);
    }

    public string Caption
    {
        get => (string)GetValue(CaptionProperty);
        set => SetValue(CaptionProperty, value);
    }

    /// <summary>The value actually drawn/animated toward Percentage -- never bound to directly,
    /// only ever set via BeginAnimation from OnPercentageChanged.</summary>
    private double AnimatedFraction
    {
        get => (double)GetValue(AnimatedFractionProperty);
        set => SetValue(AnimatedFractionProperty, value);
    }

    private bool _firstValueSet;

    public RadialGauge()
    {
        InitializeComponent();
        SizeChanged += (_, _) => Redraw();
    }

    private static void OnPercentageChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var gauge = (RadialGauge)d;
        var from = (double)e.OldValue;
        var to = (double)e.NewValue;
        if (!gauge._firstValueSet)
        {
            // No previous real reading to animate from yet -- jump straight to the first value
            // rather than animating up from an arbitrary 0, which would misrepresent "was empty."
            gauge._firstValueSet = true;
            gauge.AnimatedFraction = to;
            gauge.PercentText.Text = $"{to * 100:0}%";
            return;
        }

        var duration = (Duration)(gauge.TryFindResource("MotionDuration") ?? new Duration(TimeSpan.FromSeconds(0.14)));
        var animation = new DoubleAnimation(from, to, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } };
        gauge.BeginAnimation(AnimatedFractionProperty, animation);
    }

    private static void OnVisualPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((RadialGauge)d).Redraw();

    private void Redraw()
    {
        var size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 0) return;

        var thickness = Track.StrokeThickness;
        var radius = (size - thickness) / 2;
        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        Track.Width = Track.Height = radius * 2;

        var animated = AnimatedFraction;
        var fraction = Math.Clamp(animated, 0.0, 1.0);
        PercentText.Text = $"{animated * 100:0}%";
        CaptionText.Text = Caption;
        Arc.Stroke = ArcBrushFor(animated);

        if (fraction <= 0.001) { Arc.Data = null; return; }

        // Full circle (fraction ~1.0) can't be expressed as a single ArcSegment (start == end
        // point is ambiguous), so draw it as two half-arcs in that case.
        if (fraction >= 0.999)
        {
            var top = new Point(center.X, center.Y - radius);
            var bottom = new Point(center.X, center.Y + radius);
            var figure1 = new PathFigure(top, new[] { new ArcSegment(bottom, new Size(radius, radius), 0, false, SweepDirection.Clockwise, true) }, false);
            var figure2 = new PathFigure(bottom, new[] { new ArcSegment(top, new Size(radius, radius), 0, false, SweepDirection.Clockwise, true) }, false);
            Arc.Data = new PathGeometry(new[] { figure1, figure2 });
            return;
        }

        var startAngle = -90.0;
        var endAngle = startAngle + fraction * 360.0;
        var start = PointOnCircle(center, radius, startAngle);
        var end = PointOnCircle(center, radius, endAngle);
        var isLargeArc = fraction > 0.5;

        var segment = new ArcSegment(end, new Size(radius, radius), 0, isLargeArc, SweepDirection.Clockwise, true);
        Arc.Data = new PathGeometry(new[] { new PathFigure(start, new PathSegment[] { segment }, false) });
    }

    private static Point PointOnCircle(Point center, double radius, double angleDegrees)
    {
        var radians = angleDegrees * Math.PI / 180.0;
        return new Point(center.X + radius * Math.Cos(radians), center.Y + radius * Math.Sin(radians));
    }

    private static Brush ArcBrushFor(double percentage) => percentage switch
    {
        >= 0.95 => (Brush)Application.Current.Resources["CriticalBrush"],
        >= 0.80 => (Brush)Application.Current.Resources["WarningBrush"],
        _ => (Brush)Application.Current.Resources["AccentBrush"]
    };
}
