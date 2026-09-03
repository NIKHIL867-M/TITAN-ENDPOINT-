using System.Globalization;
using System.Windows.Data;
using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.Converters;

/// <summary>True -&gt; healthy (teal-green), False -&gt; critical (red). Used for the Custom Rule
/// wizard's API-reachability banner.</summary>
public sealed class BoolToStatusBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ThemeBrushes.Healthy : ThemeBrushes.Critical;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
