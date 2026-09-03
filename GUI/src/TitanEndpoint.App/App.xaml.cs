using System.Diagnostics;
using System.Windows;
using TitanEndpoint.App.Accessibility;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.Views;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Models;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace TitanEndpoint.App;

public partial class App : Application
{
    public static TitanFleet Fleet { get; private set; } = null!;
    public static DiskBudgetCoordinator DiskBudgets { get; } = new();
    public static LayoutPreferenceStore Layout { get; private set; } = null!;
    private DispatcherTimer? _budgetTimer;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            LogCrash(args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            LogCrash(args.ExceptionObject as Exception ?? new Exception(args.ExceptionObject?.ToString()));
        };

        try
        {
            var settings = TitanSettings.LoadOrCreateDefault();
            ApplyThemePalette(settings.UseLightTheme);
            RuntimeConfiguration.Prepare(settings);
            Fleet = new TitanFleet(settings);
            Fleet.StartAllTailers();
            Fleet.RefreshAllProcessStates();
            ApplyReducedMotion(settings.ReducedMotion);
            // Must run before any Window/UserControl is constructed -- see
            // HighContrastThemeManager's Initialize() doc comment for why.
            HighContrastThemeManager.Initialize();
            Layout = new LayoutPreferenceStore(settings.TitanRootDirectory);
            TableDensityManager.Apply(Layout.TryGetValue<bool>("TableDensity.Compact", out var compact) && compact);

            _budgetTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(30)
            };
            _budgetTimer.Tick += async (_, _) => await ApplyBudgetsSafelyAsync();
            _budgetTimer.Start();
            _ = ApplyBudgetsSafelyAsync();

            var window = new MainWindow();
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            LogCrash(ex);
            throw;
        }
    }

    /// <summary>Santosh, 2026-08-31: "add lightmode and darkmode option... should not change
    /// anything, only looks." Must run before any Window/UserControl is constructed, same
    /// requirement as HighContrastThemeManager.Initialize() just below in OnStartup, for the exact
    /// same reason: a control's Style/Setter StaticResource lookups resolve once, at the moment
    /// that control is first constructed, against whatever is in Application.Resources.
    /// MergedDictionaries at that instant. Inserted at index 0 (Palette first, Theme.xaml second)
    /// so Theme.xaml's own internal StaticResource references (WindowBgBrush, AccentBrush, etc.,
    /// used throughout its Setters) resolve against this same flat Application.Resources scope --
    /// standard WPF colors-dictionary-plus-styles-dictionary pattern, not order-sensitive beyond
    /// both needing to land in this one MergedDictionaries collection before anything reads them.</summary>
    private static void ApplyThemePalette(bool useLightTheme)
    {
        var paletteUri = new Uri(useLightTheme ? "Themes/PaletteLight.xaml" : "Themes/Palette.xaml", UriKind.Relative);
        var themeUri = new Uri("Themes/Theme.xaml", UriKind.Relative);
        Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = paletteUri });
        Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });
    }

    /// <summary>Santosh, 2026-08-31: "just add button on dark and light... no restart for that." A
    /// true zero-flicker live palette swap is not safe here without a much larger change: almost
    /// every color in this app resolves via StaticResource (fixed at the moment a control is first
    /// built, confirmed by ApplyThemePalette's own doc comment above), so re-pointing the merged
    /// dictionaries after startup would only repaint brand-new controls -- everything already on
    /// screen, and every page this session has ever visited (MainWindow._pageCache keeps them alive
    /// with their own live DispatcherTimers for the app's whole lifetime, confirmed by reading
    /// MainWindow.xaml.cs), would stay on the old palette, and a naive "just build a new MainWindow"
    /// workaround would leave those cached pages' timers running forever in the background with
    /// nothing ever stopping them -- a real leak, not a cosmetic gap. What this DOES avoid is any
    /// manual step: one click here saves the new theme and relaunches TITAN itself, so nothing has
    /// to be restarted BY the user -- confirmed safe to do even with endpoints actively running:
    /// TitanFleet.Shutdown() only stops this GUI process's own log tailers (EndpointRuntimeState.
    /// Dispose -> Tailer.Stop), never the native endpoint processes themselves, exactly like closing
    /// the window with the X already does per HOW_TO_RUN.txt's own documented behavior.</summary>
    public static void RestartWithTheme(bool useLightTheme)
    {
        try
        {
            Fleet.Settings.UseLightTheme = useLightTheme;
            Fleet.Settings.Save();
        }
        catch (Exception ex) { LogCrash(ex); }

        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath))
                Process.Start(new ProcessStartInfo { FileName = exePath, UseShellExecute = true });
        }
        catch (Exception ex) { LogCrash(ex); }

        Current.Shutdown();
    }

    /// <summary>FORU.TXT 0.4: "Reduced Motion must disable all nonessential animation globally."
    /// Every animation in this app is required to reference the "MotionDuration" resource via
    /// DynamicResource rather than a literal Duration (see Theme.xaml's ToggleSwitchStyle for the
    /// pattern) -- swapping this single resource here is therefore global and immediate, including
    /// for animations added later, not just the ones known about at the time this was written.
    /// Called once at startup and again whenever SettingsViewModel saves a changed ReducedMotion
    /// value, so the effect is live without requiring a restart.</summary>
    public static void ApplyReducedMotion(bool reducedMotion)
    {
        Current.Resources["MotionDuration"] = reducedMotion ? new Duration(TimeSpan.Zero) : new Duration(TimeSpan.FromSeconds(0.14));
        // ToggleSwitchStyle's animation cannot itself reference MotionDuration -- see Theme.xaml's
        // comment on ToggleSwitchStyleAnimated/Instant for why a Storyboard-embedded DynamicResource
        // is unsafe -- so Reduced Motion swaps which style resource "ToggleSwitchStyle" points to
        // instead. Every toggle switch must bind Style="{DynamicResource ToggleSwitchStyle}" (not
        // StaticResource) for this swap to reach already-constructed controls.
        Current.Resources["ToggleSwitchStyle"] = reducedMotion
            ? Current.Resources["ToggleSwitchStyleInstant"]
            : Current.Resources["ToggleSwitchStyleAnimated"];
    }

    private static async Task ApplyBudgetsSafelyAsync()
    {
        try { await DiskBudgets.ApplyAsync(Fleet); }
        catch (Exception ex) { LogCrash(new InvalidOperationException("Disk budget coordination failed.", ex)); }
    }

    private static void LogCrash(Exception ex)
    {
        try
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "titan_gui_crash.log");
            System.IO.File.AppendAllText(path, $"{DateTime.Now}: {ex}\n\n");
        }
        catch { /* best effort */ }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _budgetTimer?.Stop();
        Fleet?.Shutdown();
        base.OnExit(e);
    }
}
