using System.Windows;
using System.Windows.Controls;

namespace TitanEndpoint.App.Common;

/// <summary>FORU.TXT 0.4: "Extend the existing LayoutPreferenceStore to ... table density, column
/// order/width/visibility, splitter positions, selected Network workspace tab ... validate every
/// restored value." Two attached behaviors (DataGrid column state, GridSplitter row height) plus a
/// static registry so App.xaml.cs can save every currently-loaded persisted control's state once at
/// MainWindow.Closing -- the same "capture state once at shutdown" shape LayoutPreferenceStore
/// already uses for SaveWindowBounds, rather than wiring a live change-tracking event per column
/// resize/reorder. A page that was never navigated to during this session was never Loaded, so it
/// has nothing to save -- its last-saved state (from a previous session) is left untouched, not
/// overwritten with defaults.</summary>
public static class LayoutPersistence
{
    // ── DataGrid column order/width/visibility ─────────────────────────────────────────

    public static readonly DependencyProperty GridKeyProperty = DependencyProperty.RegisterAttached(
        "GridKey", typeof(string), typeof(LayoutPersistence), new PropertyMetadata(null, OnGridKeyChanged));

    public static void SetGridKey(DependencyObject element, string value) => element.SetValue(GridKeyProperty, value);
    public static string? GetGridKey(DependencyObject element) => (string?)element.GetValue(GridKeyProperty);

    private static readonly List<WeakReference<DataGrid>> RegisteredGrids = new();

    private sealed record ColumnState(string Header, double Width, int DisplayIndex, bool Visible);

    private static void OnGridKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not DataGrid grid || e.NewValue is not string) return;
        RegisteredGrids.Add(new WeakReference<DataGrid>(grid));
        grid.Loaded += (_, _) => RestoreGrid(grid);
    }

    private static void RestoreGrid(DataGrid grid)
    {
        var key = GetGridKey(grid);
        if (key is null) return;
        if (!App.Layout.TryGetValue<List<ColumnState>>($"Grid.{key}", out var saved) || saved is null) return;

        // Found live: a saved layout from before a column was added/removed/reordered in code still
        // matched each of its OWN entries by header text (safe), but DisplayIndex values are only
        // meaningful relative to the exact column set they were saved against. Applying a stale
        // DisplayIndex here silently shoved a newly-added "Retained (graph)" column off to the side
        // instead of leaving it where the current XAML declares it. Only trust DisplayIndex when the
        // live column set is unchanged (same headers, same count) from what was saved; Width/
        // Visibility are still safe to restore per-column regardless, since those never affect where
        // OTHER columns end up.
        var sameColumnSet = saved.Count == grid.Columns.Count &&
            saved.Select(s => s.Header).OrderBy(h => h, StringComparer.Ordinal)
                .SequenceEqual(grid.Columns.Select(c => c.Header as string ?? "").OrderBy(h => h, StringComparer.Ordinal));

        // Validate every restored value (FORU.TXT 0.4) -- a saved state from a build with different
        // columns must not corrupt or crash the live grid. Match by header text (stable across
        // column reordering) and ignore any saved entry that no longer has a matching real column.
        foreach (var state in saved)
        {
            var column = grid.Columns.FirstOrDefault(c => (c.Header as string) == state.Header);
            if (column is null) continue;
            if (state.Width is > 10 and < 4000) column.Width = new DataGridLength(state.Width);
            if (sameColumnSet && state.DisplayIndex >= 0 && state.DisplayIndex < grid.Columns.Count)
                column.DisplayIndex = Math.Min(state.DisplayIndex, grid.Columns.Count - 1);
            column.Visibility = state.Visible ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private static void SaveGrid(DataGrid grid)
    {
        var key = GetGridKey(grid);
        if (key is null || grid.Columns.Count == 0) return;
        var state = grid.Columns
            .Where(c => c.Header is string)
            .Select(c => new ColumnState((string)c.Header, c.ActualWidth, c.DisplayIndex, c.Visibility == Visibility.Visible))
            .ToList();
        App.Layout.SetValue($"Grid.{key}", state);
    }

    // ── GridSplitter row height ─────────────────────────────────────────────────────────

    public static readonly DependencyProperty SplitterKeyProperty = DependencyProperty.RegisterAttached(
        "SplitterKey", typeof(string), typeof(LayoutPersistence), new PropertyMetadata(null, OnSplitterKeyChanged));

    public static void SetSplitterKey(DependencyObject element, string value) => element.SetValue(SplitterKeyProperty, value);
    public static string? GetSplitterKey(DependencyObject element) => (string?)element.GetValue(SplitterKeyProperty);

    private static readonly List<WeakReference<GridSplitter>> RegisteredSplitters = new();

    private static void OnSplitterKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not GridSplitter splitter || e.NewValue is not string) return;
        RegisteredSplitters.Add(new WeakReference<GridSplitter>(splitter));
        splitter.Loaded += (_, _) => RestoreSplitter(splitter);
    }

    // The GridSplitter instances in this app all follow the same "content row / splitter row /
    // content row" layout, Grid.Row="1" with HorizontalAlignment="Stretch" -- the row it visually
    // controls is the one immediately above it.
    private static RowDefinition? TargetRow(GridSplitter splitter)
    {
        if (splitter.Parent is not Grid grid) return null;
        var row = Grid.GetRow(splitter);
        return row > 0 && row - 1 < grid.RowDefinitions.Count ? grid.RowDefinitions[row - 1] : null;
    }

    private static void RestoreSplitter(GridSplitter splitter)
    {
        var key = GetSplitterKey(splitter);
        var row = key is null ? null : TargetRow(splitter);
        if (row is null) return;
        if (App.Layout.TryGetValue<double>($"Splitter.{key}", out var height) && height > 40 && height < 4000)
            row.Height = new GridLength(height);
    }

    private static void SaveSplitter(GridSplitter splitter)
    {
        var key = GetSplitterKey(splitter);
        var row = key is null ? null : TargetRow(splitter);
        if (row is null || row.ActualHeight <= 0) return;
        App.Layout.SetValue($"Splitter.{key}", row.ActualHeight);
    }

    // ── Called once from MainWindow's Closing handler ───────────────────────────────────

    public static void SaveAll()
    {
        foreach (var weakRef in RegisteredGrids)
            if (weakRef.TryGetTarget(out var grid) && grid.IsLoaded)
                SaveGrid(grid);
        foreach (var weakRef in RegisteredSplitters)
            if (weakRef.TryGetTarget(out var splitter) && splitter.IsLoaded)
                SaveSplitter(splitter);
    }
}
