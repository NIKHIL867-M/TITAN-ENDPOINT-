using System.Windows.Controls;

namespace TitanEndpoint.App.Views;

public partial class NetworkView : UserControl
{
    private const string InvestigationTabKey = "Network.InvestigationTabIndex";
    private bool _restoringInvestigationTab;

    public NetworkView()
    {
        InitializeComponent();
        Loaded += (_, _) => RestoreInvestigationTab();
    }

    private void ProtocolTree_SelectedItemChanged(object sender, System.Windows.RoutedPropertyChangedEventArgs<object> e)
    {
        if (DataContext is ViewModels.NetworkViewModel viewModel)
            viewModel.SelectProtocolField(e.NewValue as ViewModels.ProtocolTreeNode);
    }

    /// <summary>FORU.TXT 0.4: "Extend the existing LayoutPreferenceStore to ... selected Network
    /// workspace tab." Restored once per page load (this page is cached and reused across
    /// navigation -- see MainWindow's _pageCache -- so this only ever runs on first navigation to
    /// Network in a session) and saved immediately on every selection change rather than waiting for
    /// window Closing, since the user may Alt+F4 or the process may be force-killed mid-session.</summary>
    private void RestoreInvestigationTab()
    {
        if (InvestigationTabs.Items.Count == 0) return;
        _restoringInvestigationTab = true;
        try
        {
            if (App.Layout.TryGetValue<int>(InvestigationTabKey, out var index) && index >= 0 && index < InvestigationTabs.Items.Count)
                InvestigationTabs.SelectedIndex = index;
        }
        finally { _restoringInvestigationTab = false; }
    }

    private void InvestigationTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_restoringInvestigationTab) return;
        if (sender is TabControl { SelectedIndex: >= 0 } tabs)
            App.Layout.SetValue(InvestigationTabKey, tabs.SelectedIndex);
    }
}
