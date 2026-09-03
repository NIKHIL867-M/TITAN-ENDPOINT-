using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TitanEndpoint.App.Converters;

/// <summary>Visible when the bound int equals the converter parameter. Named for its main use
/// (the Custom Rule wizard's 4 stage panels) but generic — also reused for a plain
/// count-equals-zero empty-state check.</summary>
public sealed class StageEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is int current && parameter is string s && int.TryParse(s, out var target))
            return current == target ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
