using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TitanEndpoint.App.Converters;

/// <summary>Visible when a bound count is zero (an empty-state message), Collapsed otherwise.</summary>
public sealed class ZeroToVisibleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is int i && i == 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
