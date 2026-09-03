using System.Globalization;
using System.Windows.Data;

namespace TitanEndpoint.App.Converters;

/// <summary>Small text label under each toggle switch in EndpointHeader (FORU.TXT 0.2: label
/// controls with real text, not only icon/colour meaning).</summary>
public sealed class BoolToOnOffConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? "ON" : "OFF";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
