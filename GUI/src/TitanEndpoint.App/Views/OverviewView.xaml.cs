using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class OverviewView : UserControl
{
    public OverviewView()
    {
        InitializeComponent();
    }

    private void OpenCard_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: EndpointCardViewModel card }) NavigateTo(card);
    }

    /// <summary>Makes the whole card clickable, not just its small "Open" button -- the button's
    /// own Click also fires this via event bubbling (MouseLeftButtonUp bubbles up from the button to
    /// this Border), which is a harmless redundant navigate-to-the-same-page, not a bug.</summary>
    private void Card_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement { Tag: EndpointCardViewModel card }) NavigateTo(card);
    }

    private void NavigateTo(EndpointCardViewModel card)
    {
        if (Window.GetWindow(this) is not MainWindow mainWindow) return;
        var mainVm = (MainViewModel)mainWindow.DataContext;
        var nav = mainVm.NavItems.FirstOrDefault(n => n.Page == card.TargetPage);
        if (nav is not null) mainVm.SelectedNavItem = nav;
    }
}
