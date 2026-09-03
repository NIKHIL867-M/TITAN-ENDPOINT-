using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.ViewModels;

namespace TitanEndpoint.App.Views;

public partial class FilesView : UserControl
{
    public FilesView()
    {
        InitializeComponent();
        RowActionsContextMenuHelper.Attach(FilesGrid, ((FilesViewModel)DataContext).RowActions);
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a file to hash" };
        if (dialog.ShowDialog() != true) return;
        var vm = (FilesViewModel)DataContext;
        vm.HashTool.HashFile(dialog.FileName);
    }
}
