using System.Windows.Controls;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class PortUsbView : UserControl
{
    public PortUsbView()
    {
        InitializeComponent();
        RowActionsContextMenuHelper.Attach(PortGrid, ((PortViewModel)DataContext).RowActions,
            includeProcessActions: false, openLocationHeader: "Open Mount Point");
    }
}
