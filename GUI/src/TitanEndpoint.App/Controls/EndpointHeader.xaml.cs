using System.Windows;
using System.Windows.Controls;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Controls;

public partial class EndpointHeader : UserControl
{
    public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
        nameof(Header), typeof(EndpointHeaderViewModel), typeof(EndpointHeader),
        new PropertyMetadata(null, OnHeaderChanged));

    public EndpointHeaderViewModel? Header
    {
        get => (EndpointHeaderViewModel?)GetValue(HeaderProperty);
        set => SetValue(HeaderProperty, value);
    }

    public EndpointHeader()
    {
        InitializeComponent();
    }

    private static void OnHeaderChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is EndpointHeaderViewModel old) old.DetailsRequested -= OnDetails;
        if (e.NewValue is EndpointHeaderViewModel newVm) newVm.DetailsRequested += OnDetails;
    }

    private static void OnDetails(string message) =>
        MessageBox.Show(Application.Current?.MainWindow, message, "Endpoint Details", MessageBoxButton.OK, MessageBoxImage.Information);
}
