using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace TitanEndpoint.App.Controls;

/// <summary>One edge on the Correlation Graph tab's live endpoint-flow diagram. Mirrors
/// RadialGauge's established animation convention exactly (BeginAnimation off a real DP change,
/// duration read fresh from "MotionDuration" at animation-start time rather than baked into a
/// Storyboard, which App.xaml.cs's ApplyReducedMotion doc comment specifically warns is unsafe for
/// a Storyboard-embedded DynamicResource) so Reduced Motion collapses this to an instant snap like
/// every other animation in the app, with no separate a11y wiring needed here.
///
/// Two independent animations compose: the control's own Opacity fades in once, the first time this
/// edge ever appears (a brand new endpoint pair the Correlator just joined); StrokeThickness/the
/// line's own Opacity separately animate toward a log-scaled target every time Count grows, so one
/// dominant pair's line can never visually bury a rarer real one. A brief scale "pulse" on the count
/// badge gives a live, non-static "something just happened" cue on every real increase after the
/// first -- skipped outright under Reduced Motion rather than played at zero duration.</summary>
public partial class FlowEdgeControl : UserControl
{
    public static readonly DependencyProperty X1Property = DependencyProperty.Register(nameof(X1), typeof(double), typeof(FlowEdgeControl), new PropertyMetadata(0.0, OnGeometryChanged));
    public static readonly DependencyProperty Y1Property = DependencyProperty.Register(nameof(Y1), typeof(double), typeof(FlowEdgeControl), new PropertyMetadata(0.0, OnGeometryChanged));
    public static readonly DependencyProperty X2Property = DependencyProperty.Register(nameof(X2), typeof(double), typeof(FlowEdgeControl), new PropertyMetadata(0.0, OnGeometryChanged));
    public static readonly DependencyProperty Y2Property = DependencyProperty.Register(nameof(Y2), typeof(double), typeof(FlowEdgeControl), new PropertyMetadata(0.0, OnGeometryChanged));
    public static readonly DependencyProperty CountProperty = DependencyProperty.Register(nameof(Count), typeof(long), typeof(FlowEdgeControl), new PropertyMetadata(0L, OnCountChanged));
    public static readonly DependencyProperty CountTextProperty = DependencyProperty.Register(nameof(CountText), typeof(string), typeof(FlowEdgeControl), new PropertyMetadata("", OnCountTextChanged));
    public static readonly DependencyProperty ToolTipTextProperty = DependencyProperty.Register(nameof(ToolTipText), typeof(string), typeof(FlowEdgeControl), new PropertyMetadata("", OnToolTipTextChanged));
    /// <summary>Round 23 ("make it more interactable"): true while a node or pair filter is active
    /// AND this edge is not part of it -- lets a clicked node/edge visually stand out against the
    /// rest of the pentagon instead of leaving every line at equal weight regardless of selection.</summary>
    public static readonly DependencyProperty DimmedProperty = DependencyProperty.Register(nameof(Dimmed), typeof(bool), typeof(FlowEdgeControl), new PropertyMetadata(false, OnDimmedChanged));

    public double X1 { get => (double)GetValue(X1Property); set => SetValue(X1Property, value); }
    public double Y1 { get => (double)GetValue(Y1Property); set => SetValue(Y1Property, value); }
    public double X2 { get => (double)GetValue(X2Property); set => SetValue(X2Property, value); }
    public double Y2 { get => (double)GetValue(Y2Property); set => SetValue(Y2Property, value); }
    public long Count { get => (long)GetValue(CountProperty); set => SetValue(CountProperty, value); }
    public string CountText { get => (string)GetValue(CountTextProperty); set => SetValue(CountTextProperty, value); }
    public string ToolTipText { get => (string)GetValue(ToolTipTextProperty); set => SetValue(ToolTipTextProperty, value); }
    public bool Dimmed { get => (bool)GetValue(DimmedProperty); set => SetValue(DimmedProperty, value); }

    private bool _firstCountSet;

    public FlowEdgeControl()
    {
        InitializeComponent();
        Opacity = 0;
        Loaded += (_, _) => PlayEntranceFade();
        Cursor = System.Windows.Input.Cursors.Hand;
        // Santosh, Round 22: "if I click on that number, what is the point of that number" -- the
        // count badge was tooltip-only. DataContext is the FlowEdgeViewModel from the ItemTemplate,
        // so a plain click here can drive its SelectCommand without any new dependency property.
        MouseLeftButtonDown += (_, e) =>
        {
            if (DataContext is TitanEndpoint.App.ViewModels.FlowEdgeViewModel edge && edge.SelectCommand.CanExecute(null))
                edge.SelectCommand.Execute(null);
            e.Handled = true;
        };
    }

    private const double DimmedOpacity = 0.16;

    private void PlayEntranceFade()
    {
        var duration = MotionDuration();
        var target = Dimmed ? DimmedOpacity : 1.0;
        if (duration.TimeSpan == TimeSpan.Zero) { Opacity = target; return; }
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, target, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } });
    }

    /// <summary>Re-targets the control's own Opacity via BeginAnimation, same convention as every
    /// other animation here -- composes safely with <see cref="PlayEntranceFade"/> since whichever
    /// one runs last always wins with the currently-correct target (PlayEntranceFade reads Dimmed
    /// fresh), so this never races the one-time entrance fade into ending at the wrong value.</summary>
    private static void OnDimmedChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var control = (FlowEdgeControl)d;
        var target = (bool)e.NewValue ? DimmedOpacity : 1.0;
        var duration = control.MotionDuration();
        if (duration.TimeSpan == TimeSpan.Zero) { control.Opacity = target; return; }
        control.BeginAnimation(OpacityProperty, new DoubleAnimation(target, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } });
    }

    private Duration MotionDuration() => (Duration)(TryFindResource("MotionDuration") ?? new Duration(TimeSpan.FromSeconds(0.14)));

    private static void OnGeometryChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((FlowEdgeControl)d).Redraw();

    private void Redraw()
    {
        EdgeLine.X1 = X1; EdgeLine.Y1 = Y1; EdgeLine.X2 = X2; EdgeLine.Y2 = Y2;
        var midX = (X1 + X2) / 2;
        var midY = (Y1 + Y2) / 2;
        Canvas.SetLeft(Badge, midX - 11);
        Canvas.SetTop(Badge, midY - 9);
    }

    private static void OnCountTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((FlowEdgeControl)d).CountTextBlock.Text = (string)e.NewValue;

    private static void OnToolTipTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var control = (FlowEdgeControl)d;
        control.ToolTip = e.NewValue;
        control.Badge.ToolTip = e.NewValue;
    }

    /// <summary>Log-scaled so one endpoint pair that dominates activity cannot visually blot out a
    /// rarer but still real pair -- every edge that has ever connected stays visible, matching "no
    /// junk" without ever hiding a real link.</summary>
    private static void OnCountChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var control = (FlowEdgeControl)d;
        var count = (long)e.NewValue;
        var targetThickness = Math.Clamp(1.75 + Math.Log(count + 1) * 2.1, 1.75, 13);
        var targetOpacity = Math.Clamp(0.32 + Math.Log(count + 1) * 0.11, 0.32, 1.0);
        var duration = control.MotionDuration();

        if (!control._firstCountSet)
        {
            control._firstCountSet = true;
            control.EdgeLine.StrokeThickness = targetThickness;
            control.EdgeLine.Opacity = targetOpacity;
            return;
        }

        if (duration.TimeSpan == TimeSpan.Zero)
        {
            control.EdgeLine.StrokeThickness = targetThickness;
            control.EdgeLine.Opacity = targetOpacity;
        }
        else
        {
            var easeOut = new QuadraticEase { EasingMode = EasingMode.EaseOut };
            control.EdgeLine.BeginAnimation(System.Windows.Shapes.Line.StrokeThicknessProperty,
                new DoubleAnimation(control.EdgeLine.StrokeThickness, targetThickness, duration) { EasingFunction = easeOut });
            control.EdgeLine.BeginAnimation(OpacityProperty,
                new DoubleAnimation(control.EdgeLine.Opacity, targetOpacity, duration) { EasingFunction = easeOut });

            var pulse = new DoubleAnimationUsingKeyFrames();
            pulse.KeyFrames.Add(new EasingDoubleKeyFrame(1.28, KeyTime.FromPercent(0.35), new QuadraticEase { EasingMode = EasingMode.EaseOut }));
            pulse.KeyFrames.Add(new EasingDoubleKeyFrame(1.0, KeyTime.FromPercent(1.0), new QuadraticEase { EasingMode = EasingMode.EaseIn }));
            pulse.Duration = new Duration(TimeSpan.FromSeconds(Math.Max(0.3, duration.TimeSpan.TotalSeconds * 3)));
            control.BadgeScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, pulse);
            control.BadgeScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, pulse);
        }
    }
}
