using System.Collections.ObjectModel;
using System.IO;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    public ObservableCollection<EndpointSettingsRowViewModel> Rows { get; } = new();

    private string _customRuleDataDirectory;
    public string CustomRuleDataDirectory
    {
        get => _customRuleDataDirectory;
        set => SetField(ref _customRuleDataDirectory, value);
    }

    private string _globalDiskBudgetGb;
    public string GlobalDiskBudgetGb
    {
        get => _globalDiskBudgetGb;
        set => SetField(ref _globalDiskBudgetGb, value);
    }
    private string _minimumFreeSpaceGb;
    public string MinimumFreeSpaceGb { get => _minimumFreeSpaceGb; set => SetField(ref _minimumFreeSpaceGb, value); }

    private string _customRuleApiBaseUrl;
    public string CustomRuleApiBaseUrl
    {
        get => _customRuleApiBaseUrl;
        set => SetField(ref _customRuleApiBaseUrl, value);
    }

    private bool _reducedMotion;
    public bool ReducedMotion
    {
        get => _reducedMotion;
        set => SetField(ref _reducedMotion, value);
    }

    // Santosh, 2026-08-31: "just add button on dark and light... no restart for that." UseLightTheme
    // is now toggled from the top command bar's one-click, auto-relaunching button (App.
    // RestartWithTheme), not from this page's Save Settings flow -- no bound property needed here
    // anymore.

    /// <summary>FORU.TXT 0.4: "table density" -- a live presentation preference persisted through
    /// LayoutPreferenceStore (not TitanSettings/settings.json), so unlike ReducedMotion above it
    /// applies and saves immediately on toggle rather than waiting for the Save Settings button; it
    /// carries no policy semantics that need validation before taking effect.</summary>
    public bool CompactTableDensity
    {
        get => TableDensityManager.IsCompact;
        set
        {
            if (TableDensityManager.IsCompact == value) return;
            TableDensityManager.Apply(value);
            App.Layout.SetValue("TableDensity.Compact", value);
            OnPropertyChanged();
        }
    }

    private string _saveStatusText = "";
    public string SaveStatusText { get => _saveStatusText; private set => SetField(ref _saveStatusText, value); }

    public RelayCommand SaveCommand { get; }

    public SettingsViewModel()
    {
        _customRuleDataDirectory = App.Fleet.Settings.CustomRuleDataDirectory;
        _customRuleApiBaseUrl = App.Fleet.Settings.CustomRuleApiBaseUrl;
        _reducedMotion = App.Fleet.Settings.ReducedMotion;
        _globalDiskBudgetGb = (App.Fleet.Settings.GlobalDiskBudgetBytes / (1024.0 * 1024 * 1024)).ToString("0.###");
        _minimumFreeSpaceGb = (App.Fleet.Settings.MinimumFreeSpaceReserveBytes / (1024.0 * 1024 * 1024)).ToString("0.###");
        foreach (var def in App.Fleet.Settings.Endpoints)
        {
            if (def.Id == EndpointId.CustomRule) continue;
            Rows.Add(new EndpointSettingsRowViewModel(def));
        }

        SaveCommand = new RelayCommand(Save);
    }

    private async void Save()
    {
            var settings = App.Fleet.Settings;
            var endpointSnapshots = Rows.ToDictionary(row => row, row => row.Capture());
            var previousCustomRuleDirectory = settings.CustomRuleDataDirectory;
            var previousApiBaseUrl = settings.CustomRuleApiBaseUrl;
            var previousBudget = settings.GlobalDiskBudgetBytes;
            var previousReserve = settings.MinimumFreeSpaceReserveBytes;
            var previousReducedMotion = settings.ReducedMotion;
            try
            {
                var errors = Validate(out var budgetBytes, out var reserveBytes);
                if (errors.Count > 0)
                {
                    SaveStatusText = "Not saved: " + string.Join(" ", errors);
                    return;
                }

                foreach (var row in Rows) row.Apply();
                settings.CustomRuleDataDirectory = CustomRuleDataDirectory.Trim();
                settings.CustomRuleApiBaseUrl = CustomRuleApiBaseUrl.TrimEnd('/');
                settings.ReducedMotion = ReducedMotion;
                settings.GlobalDiskBudgetBytes = budgetBytes;
                settings.MinimumFreeSpaceReserveBytes = reserveBytes;
                RuntimeConfiguration.Prepare(settings);
                settings.Save();
                App.ApplyReducedMotion(settings.ReducedMotion);

                var missing = Rows.Where(r => !File.Exists(Environment.ExpandEnvironmentVariables(r.ExePath)))
                    .Select(r => r.DisplayName).ToList();
                var warning = missing.Count == 0 ? "" : $" Warning: executable currently missing for {string.Join(", ", missing)}.";
                var budgetResults = await App.DiskBudgets.ApplyAsync(App.Fleet);
                var applied = budgetResults.Count(result => result.State == "Applied");
                var pending = budgetResults.Count(result => result.State == "Pending");
                var rejected = budgetResults.Count(result => result.State == "Rejected");
                SaveStatusText = $"Saved durably at {DateTime.Now:HH:mm:ss}. Retention budgets: {applied} applied, {pending} pending, {rejected} rejected.{warning}";
            }
            catch (Exception ex)
            {
                foreach (var (row, snapshot) in endpointSnapshots) row.Restore(snapshot);
                settings.CustomRuleDataDirectory = previousCustomRuleDirectory;
                settings.CustomRuleApiBaseUrl = previousApiBaseUrl;
                settings.GlobalDiskBudgetBytes = previousBudget;
                settings.MinimumFreeSpaceReserveBytes = previousReserve;
                settings.ReducedMotion = previousReducedMotion;
                try { RuntimeConfiguration.Prepare(settings); } catch { /* preserve original save error */ }
                SaveStatusText = $"Save failed: {ex.Message}";
            }
    }

    private List<string> Validate(out long budgetBytes, out long reserveBytes)
    {
        var errors = Rows.SelectMany(r => r.Validate()).ToList();
        budgetBytes = 0;
        if (!double.TryParse(GlobalDiskBudgetGb, out var gb) || double.IsNaN(gb) || double.IsInfinity(gb) || gb < 0.1 || gb > 1024)
            errors.Add("Global disk budget must be a number from 0.1 through 1024 GB.");
        else
            budgetBytes = checked((long)(gb * 1024 * 1024 * 1024));
        reserveBytes = 0;
        if (!double.TryParse(MinimumFreeSpaceGb, out var reserveGb) || double.IsNaN(reserveGb) ||
            double.IsInfinity(reserveGb) || reserveGb < 0.1 || reserveGb > 1024)
            errors.Add("Minimum free-space reserve must be a number from 0.1 through 1024 GB.");
        else reserveBytes = checked((long)(reserveGb * 1024 * 1024 * 1024));

        if (string.IsNullOrWhiteSpace(CustomRuleDataDirectory))
            errors.Add("Custom Rule data directory is required.");
        else
        {
            try { _ = Path.GetFullPath(Environment.ExpandEnvironmentVariables(CustomRuleDataDirectory)); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            { errors.Add("Custom Rule data directory is invalid."); }
        }
        if (!Uri.TryCreate(CustomRuleApiBaseUrl, UriKind.Absolute, out var apiUri) ||
            apiUri.Scheme != Uri.UriSchemeHttp || !apiUri.IsLoopback || apiUri.Port is <= 0 or > 65535)
            errors.Add("Custom Rule API URL must be a loopback HTTP address such as http://127.0.0.1:8765.");
        return errors;
    }
}
