using System.Windows.Controls;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class ApplicationsView : UserControl
{
    public ApplicationsView()
    {
        InitializeComponent();
        RowActionsContextMenuHelper.Attach(ApplicationActivityGrid, ((ApplicationsViewModel)DataContext).RowActions);
    }
}
