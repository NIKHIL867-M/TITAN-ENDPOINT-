using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TitanEndpoint.App.Converters;

/// <summary>true -> the star/pixel size given in ConverterParameter (default "1*"); false -> zero.
/// Santosh, 2026-08-31: "that show the table only button... it is not working" -- a RowDefinition.Style
/// DataTrigger bound via ElementName did not reliably re-measure the Grid when toggled (confirmed
/// live: BoundingRectangle never changed). Binding Height directly through a converter is the
/// standard, reliably-working WPF pattern for this exact case.</summary>
public sealed class BoolToGridLengthConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var isTrue = value is bool b && b;
        if (!isTrue) return new GridLength(0);
        var spec = parameter as string ?? "1*";
        if (spec.EndsWith('*'))
        {
            var factorText = spec[..^1];
            var factor = string.IsNullOrEmpty(factorText) ? 1.0 : double.Parse(factorText, CultureInfo.InvariantCulture);
            return new GridLength(factor, GridUnitType.Star);
        }
        return new GridLength(double.Parse(spec, CultureInfo.InvariantCulture));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
