using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Common;

/// <summary>Builds the "Open File Location / Stop / Isolate" row context menu in code-behind
/// instead of declarative Command bindings (Santosh, 2026-08-06: "open location... not opening
/// and also other option either").
///
/// Root cause: Process/Files/Applications/Port each declared the menu inline inside a
/// DataGridRow's Style Setter, with Command="{Binding DataContext.RowActions.X, ElementName=...}".
/// A WPF ContextMenu's items render in a disconnected Popup that is not part of the page's
/// NameScope, so that ElementName lookup silently resolves to nothing -- the menu still opens
/// (CommandParameter's RelativeSource AncestorType=ContextMenu walk works fine, since that's
/// resolved from inside the popup's own tree), but every item's Command stays null and clicks are
/// no-ops. No binding error is visible without a debugger attached, which is how this shipped
/// unnoticed. Plain event handlers with directly captured C# references have no such ambiguity.</summary>
public static class RowActionsContextMenuHelper
{
    public static void Attach(DataGrid grid, RowActionsViewModel actions, bool includeProcessActions = true, string openLocationHeader = "Open File Location")
    {
        grid.PreviewMouseRightButtonDown += (_, e) =>
        {
            var row = FindAncestorRow(e.OriginalSource as DependencyObject);
            if (row?.Item is not IActionableRow actionable) return;

            grid.SelectedItem = row.Item;

            var menu = new ContextMenu();
            menu.Items.Add(BuildItem(openLocationHeader, () => actions.OpenLocationCommand.Execute(actionable)));

            if (includeProcessActions)
            {
                menu.Items.Add(new Separator());
                menu.Items.Add(BuildItem("Stop Process", () => actions.StopCommand.Execute(actionable), destructive: true));
                menu.Items.Add(BuildItem("Isolate (block network)", () => actions.IsolateCommand.Execute(actionable), destructive: true));
                menu.Items.Add(new Separator());
                menu.Items.Add(BuildItem("Remove Isolation", () => actions.RemoveIsolationCommand.Execute(actionable)));
            }

            menu.PlacementTarget = grid;
            menu.IsOpen = true;
            e.Handled = true;
        };
    }

    private static MenuItem BuildItem(string header, Action onClick, bool destructive = false)
    {
        var item = new MenuItem { Header = header };
        if (destructive && Application.Current.TryFindResource("DestructiveMenuItemStyle") is Style style)
            item.Style = style;
        item.Click += (_, _) => onClick();
        return item;
    }

    private static DataGridRow? FindAncestorRow(DependencyObject? source)
    {
        while (source != null && source is not DataGridRow)
            source = VisualTreeHelper.GetParent(source);
        return source as DataGridRow;
    }
}
