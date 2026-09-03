using System.Windows;
using System.Windows.Input;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

/// <summary>
/// Code-behind for FollowStreamWindow. The window is a focused dialog/drawer for TCP stream
/// reconstruction. It is constructed with a pre-built FollowStreamViewModel (which drives its
/// own Load() call) and displayed as a non-modal window owned by the main window.
/// </summary>
public partial class FollowStreamWindow : Window
{
    private readonly FollowStreamViewModel _vm;

    public FollowStreamWindow(FollowStreamViewModel vm)
    {
        InitializeComponent();
        _vm        = vm ?? throw new ArgumentNullException(nameof(vm));
        DataContext = _vm;
    }

    // ---- View mode radio buttons ----

    private void ViewMode_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton rb) return;
        if (!IsLoaded) return;
        _vm.ViewMode = rb.Tag?.ToString() switch
        {
            "Hex"   => FollowStreamViewModel.StreamViewMode.Hex,
            "Ascii" => FollowStreamViewModel.StreamViewMode.Ascii,
            "Raw"   => FollowStreamViewModel.StreamViewMode.Raw,
            _       => FollowStreamViewModel.StreamViewMode.Text
        };
    }

    // ---- Direction filter combo ----

    private void Direction_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        _vm.ActiveDirectionFilter = ((System.Windows.Controls.ComboBox)sender).SelectedIndex switch
        {
            1 => FollowStreamViewModel.DirectionFilter.AToB,
            2 => FollowStreamViewModel.DirectionFilter.BToA,
            _ => FollowStreamViewModel.DirectionFilter.Both
        };
    }

    // ---- Search box Enter key ----

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Return || e.Key == Key.Enter)
        {
            _vm.SearchNextCommand.Execute(null);
            e.Handled = true;
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Close();
            e.Handled = true;
        }
        base.OnKeyDown(e);
    }
}
