using System.Globalization;
using System.Windows.Data;
using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.Converters;

/// <summary>Green dot once the native collector has acknowledged an entry, grey while pending.</summary>
public sealed class AppliedToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ThemeBrushes.Healthy : ThemeBrushes.Disabled;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
