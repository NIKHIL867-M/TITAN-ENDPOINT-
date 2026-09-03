using System.Windows;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class DiagnosticsWindow : Window
{
    public DiagnosticsWindow(EndpointDiagnosticsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        Closed += (_, _) => viewModel.Stop();
    }
}
