using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace TitanEndpoint.App.Controls;

/// <summary>Task Manager "Performance" tab style live moving graph -- FORU.TXT GUI-upgrade ask
/// ("if it's like graph motion also I would be great, just for the looks"). Filled area + line +
/// sparse recessive gridlines, one series, real values only (no fabricated data; System Health's
/// caller computes a genuine events/sec figure from the fleet's actual RecordsWritten counters).
/// Shares Sparkline's live-redraw-on-CollectionChanged fix rather than depending on the DependencyProperty
/// reference changing.</summary>
public partial class PerformanceGraph : UserControl
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(PerformanceGraph), new PropertyMetadata(null, OnValuesChanged));

    public static readonly DependencyProperty UnitProperty = DependencyProperty.Register(
        nameof(Unit), typeof(string), typeof(PerformanceGraph), new PropertyMetadata("", OnValuesChanged));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    /// <summary>Short unit label appended to the current-value readout, e.g. "/s".</summary>
    public string Unit
    {
        get => (string)GetValue(UnitProperty);
        set => SetValue(UnitProperty, value);
    }

    public PerformanceGraph()
    {
        InitializeComponent();
        SizeChanged += (_, _) => Redraw();
    }

    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var graph = (PerformanceGraph)d;
        if (e.Property == ValuesProperty)
        {
            if (e.OldValue is INotifyCollectionChanged oldNotifying) oldNotifying.CollectionChanged -= graph.OnValuesCollectionChanged;
            if (e.NewValue is INotifyCollectionChanged newNotifying) newNotifying.CollectionChanged += graph.OnValuesCollectionChanged;
        }
        graph.Redraw();
    }

    private void OnValuesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => Redraw();

    private void Redraw()
    {
        var values = Values;
        var width = ActualWidth;
        var height = ActualHeight;
        GridLines.Children.Clear();

        if (values is null || values.Count < 2 || width <= 0 || height <= 0)
        {
            Line.Points.Clear();
            Fill.Points.Clear();
            CurrentValueText.Text = "";
            ScaleMaxText.Text = "";
            ScaleMinText.Text = "";
            return;
        }

        var max = Math.Max(values.Max(), 1.0); // real floor so an all-zero window still draws a flat baseline, not a divide-by-zero spike
        const double min = 0.0;
        var range = max - min;

        // Four sparse horizontal gridlines -- recessive, never competing with the data line.
        for (var i = 1; i <= 3; i++)
        {
            var y = height * i / 4.0;
            GridLines.Children.Add(new System.Windows.Shapes.Line
            {
                X1 = 0, Y1 = y, X2 = width, Y2 = y,
                Stroke = (Brush)Application.Current.Resources["BorderBrush2"],
                StrokeThickness = 1, Opacity = 0.5
            });
        }

        var points = new PointCollection(values.Count);
        var stepX = width / (values.Count - 1);
        for (var i = 0; i < values.Count; i++)
        {
            var normalized = (values[i] - min) / range;
            var y = height - normalized * (height - 6) - 3;
            points.Add(new Point(i * stepX, y));
        }
        Line.Points = points;

        var fillPoints = new PointCollection(points) { new Point(width, height), new Point(0, height) };
        Fill.Points = fillPoints;

        var current = values[^1];
        CurrentValueText.Text = $"{current:0.#}{Unit}";
        ScaleMaxText.Text = $"{max:0.#}{Unit}";
        ScaleMinText.Text = $"0{Unit}";
    }
}
