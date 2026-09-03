using System.Windows;
using System.Windows.Controls;
using TitanEndpoint.App.Accessibility;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.ViewModels;
using TitanEndpoint.App.Views;

namespace TitanEndpoint.App;

public partial class MainWindow : Window
{
    private readonly Dictionary<AppPage, UserControl> _pageCache = new();
    private MainViewModel ViewModel => (MainViewModel)DataContext;

    // FORU.TXT 0.4: "The 12-item navigation rail must scroll, may collapse to labelled icons, and
    // must retain selection and focus." Below this width the rail narrows to icon-only; above it,
    // full labels. A single code-driven breakpoint (classic WPF has no built-in AdaptiveTrigger --
    // that is UWP/WinUI-only) rather than a XAML VisualStateManager, matching this project's
    // existing "decide it in code, once" pattern already used for WindowState (see the constructor
    // comment below for why a XAML-only approach lost that exact fight before).
    private const double NavRailCollapseWidthThreshold = 1180;
    private const double NavRailExpandedWidth = 200;
    private const double NavRailCollapsedWidth = 56;

    public static readonly DependencyProperty NavLabelVisibilityProperty = DependencyProperty.Register(
        nameof(NavLabelVisibility), typeof(Visibility), typeof(MainWindow), new PropertyMetadata(Visibility.Visible));
    public Visibility NavLabelVisibility
    {
        get => (Visibility)GetValue(NavLabelVisibilityProperty);
        set => SetValue(NavLabelVisibilityProperty, value);
    }

    public static readonly DependencyProperty NavIconOnlyVisibilityProperty = DependencyProperty.Register(
        nameof(NavIconOnlyVisibility), typeof(Visibility), typeof(MainWindow), new PropertyMetadata(Visibility.Collapsed));
    public Visibility NavIconOnlyVisibility
    {
        get => (Visibility)GetValue(NavIconOnlyVisibilityProperty);
        set => SetValue(NavIconOnlyVisibilityProperty, value);
    }

    public MainWindow()
    {
        InitializeComponent();
        // WindowState is fully decided here in code, not in XAML -- a XAML-declared
        // WindowState="Maximized" default was found to silently win over any later code-based
        // WindowState change (constructor, SourceInitialized, or Loaded all failed to override it),
        // discarding a restored Normal size on every launch. Deciding it exactly once, here, before
        // Show() is ever reached, removes that race entirely.
        if (!App.Layout.RestoreWindowBounds(this)) WindowState = WindowState.Maximized;
        Loaded += (_, _) =>
        {
            ViewModel.NavigateRequested += Navigate;
            Navigate(ViewModel.CurrentPage);
            LiveRegionAnnouncer.Initialize(this);
            ApplyNavRailBreakpoint(ActualWidth);
        };
        SizeChanged += (_, e) => ApplyNavRailBreakpoint(e.NewSize.Width);
        Closing += (_, _) =>
        {
            App.Layout.SaveWindowBounds(this);
            LayoutPersistence.SaveAll();
        };
    }

    private bool? _navRailCollapsed;

    private void ApplyNavRailBreakpoint(double windowWidth)
    {
        var shouldCollapse = windowWidth < NavRailCollapseWidthThreshold;
        if (_navRailCollapsed == shouldCollapse) return; // avoid redundant layout work on every SizeChanged tick
        _navRailCollapsed = shouldCollapse;

        NavColumn.Width = new GridLength(shouldCollapse ? NavRailCollapsedWidth : NavRailExpandedWidth);
        NavLabelVisibility = shouldCollapse ? Visibility.Collapsed : Visibility.Visible;
        NavIconOnlyVisibility = shouldCollapse ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Navigate(AppPage page)
    {
        if (!_pageCache.TryGetValue(page, out var view))
        {
            view = CreateView(page);
            _pageCache[page] = view;
        }
        ContentHost.Content = view;
    }

    private static UserControl CreateView(AppPage page) => page switch
    {
        AppPage.Overview => new OverviewView(),
        AppPage.Process => new ProcessView(),
        AppPage.Network => new NetworkView(),
        AppPage.Applications => new ApplicationsView(),
        AppPage.Files => new FilesView(),
        AppPage.PortUsb => new PortUsbView(),
        AppPage.Correlation => new CorrelationView(),
        AppPage.CorrelationGraph => new CorrelationGraphView(),
        AppPage.IncidentGraph => new IncidentGraphView(),
        AppPage.StixExport => new StixExportView(),
        AppPage.CustomRules => new CustomRulesView(),
        AppPage.Alerts => new AlertsView(),
        AppPage.UnifiedLogs => new UnifiedLogsView(),
        AppPage.SystemHealth => new SystemHealthView(),
        AppPage.Settings => new SettingsView(),
        _ => new PlaceholderView(page.ToString())
    };
}
