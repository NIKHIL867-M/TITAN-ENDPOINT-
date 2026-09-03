using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;

namespace TitanEndpoint.App.Controls;

public partial class Sparkline : UserControl
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(Sparkline),
        new PropertyMetadata(null, OnValuesChanged));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public Sparkline()
    {
        InitializeComponent();
        SizeChanged += (_, _) => Redraw();
    }

    /// <summary>Found live: the callers (Overview's RamSamples/DiskSamples) are ObservableCollection
    /// instances mutated in place every tick (Add + RemoveAt), never reassigned to a new collection
    /// -- so the DependencyProperty's own change notification alone never fires again after the
    /// first bind, and the line was silently frozen at whatever it looked like on first render. This
    /// is the actual "graph motion" gap: subscribing to CollectionChanged is what makes it live.</summary>
    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var sparkline = (Sparkline)d;
        if (e.OldValue is INotifyCollectionChanged oldNotifying) oldNotifying.CollectionChanged -= sparkline.OnValuesCollectionChanged;
        if (e.NewValue is INotifyCollectionChanged newNotifying) newNotifying.CollectionChanged += sparkline.OnValuesCollectionChanged;
        sparkline.Redraw();
    }

    private void OnValuesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => Redraw();

    private void Redraw()
    {
        var values = Values;
        if (values is null || values.Count < 2 || ActualWidth <= 0 || ActualHeight <= 0)
        {
            Line.Points.Clear();
            return;
        }

        var max = values.Max();
        var min = values.Min();
        var range = max - min;
        if (range < 0.0001) range = 1;

        var points = new System.Windows.Media.PointCollection(values.Count);
        var stepX = ActualWidth / (values.Count - 1);
        for (var i = 0; i < values.Count; i++)
        {
            var normalized = (values[i] - min) / range;
            var y = ActualHeight - normalized * (ActualHeight - 4) - 2;
            points.Add(new Point(i * stepX, y));
        }
        Line.Points = points;
    }
}
