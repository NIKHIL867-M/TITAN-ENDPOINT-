using System.Windows;

namespace TitanEndpoint.App.Common;

/// <summary>FORU.TXT 0.4: "compact/comfortable table-density modes." Unlike
/// HighContrastThemeManager's brush-mutation approach (needed there because every consumer binds via
/// StaticResource, which freezes the resolved object at parse time), DataGrid's RowHeight and
/// DataGridCell's Padding Setters in Theme.xaml reference TableRowHeight/TableCellPadding via
/// DynamicResource, which DOES re-resolve when the dictionary entry itself is replaced -- so this can
/// simply reassign Application.Resources[key] wholesale rather than mutating an existing object in
/// place.</summary>
public static class TableDensityManager
{
    private static readonly double ComfortableRowHeight = 24;
    private static readonly Thickness ComfortableCellPadding = new(6, 2, 6, 2);
    private static readonly double CompactRowHeight = 19;
    private static readonly Thickness CompactCellPadding = new(5, 0, 5, 0);

    public static bool IsCompact { get; private set; }

    public static void Apply(bool compact)
    {
        IsCompact = compact;
        Application.Current.Resources["TableRowHeight"] = compact ? CompactRowHeight : ComfortableRowHeight;
        Application.Current.Resources["TableCellPadding"] = compact ? CompactCellPadding : ComfortableCellPadding;
    }
}
