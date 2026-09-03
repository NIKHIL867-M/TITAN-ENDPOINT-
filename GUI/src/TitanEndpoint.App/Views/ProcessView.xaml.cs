using System.Windows.Controls;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class ProcessView : UserControl
{
    public ProcessView()
    {
        InitializeComponent();
        RowActionsContextMenuHelper.Attach(ProcessGrid, ((ProcessViewModel)DataContext).RowActions);
    }
}
