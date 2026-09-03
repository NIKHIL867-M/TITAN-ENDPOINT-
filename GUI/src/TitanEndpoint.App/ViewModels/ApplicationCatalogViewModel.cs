using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// Full discovered/installed/running application catalogue, paged and filterable (FORU.TXT
/// section 9.2/9.4) — reads config\application_catalog.json (see
/// APP\src\applog_monitor.cpp::WriteApplicationCatalog, written every ~20s). Distinct from
/// ApplicationWatchlistViewModel (the currently-monitored set) — this page shows EVERYTHING
/// discoverable, with a Monitor toggle per row that delegates to the watchlist view model so
/// there is exactly one write path for watchlist changes.
/// </summary>
public sealed class ApplicationCatalogViewModel : ViewModelBase
{
    private const int PageSize = 25;

    public ObservableCollection<ApplicationCatalogEntryViewModel> PageRows { get; } = new();

    private List<ApplicationCatalogEntryViewModel> _allEntries = new();
    private readonly ApplicationWatchlistViewModel _watchlist;
    private readonly string _catalogPath;
    private readonly DispatcherTimer _timer;

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) { _page = 0; ApplyFilterAndPage(); } }
    }

    private int _page;
    public int Page { get => _page; private set => SetField(ref _page, value); }

    private string _totalsText = "Waiting for catalogue...";
    public string TotalsText { get => _totalsText; private set => SetField(ref _totalsText, value); }

    private string _pageText = "";
    public string PageText { get => _pageText; private set => SetField(ref _pageText, value); }

    private DateTime? _generatedAtUtc;
    private string _freshnessText = "Unavailable";
    public string FreshnessText { get => _freshnessText; private set => SetField(ref _freshnessText, value); }

    public RelayCommand NextPageCommand { get; }
    public RelayCommand PrevPageCommand { get; }
    public RelayCommand ToggleMonitorCommand { get; }

    public ApplicationCatalogViewModel(ApplicationWatchlistViewModel watchlist, EndpointDefinition appDefinition)
    {
        _watchlist = watchlist;
        var exeDir = System.IO.Path.GetDirectoryName(appDefinition.ResolveExePath()) ?? "";
        _catalogPath = string.IsNullOrEmpty(exeDir) ? "" : System.IO.Path.Combine(exeDir, "config", "application_catalog.json");

        NextPageCommand = new RelayCommand(() => { Page++; ApplyFilterAndPage(); }, () => (Page + 1) * PageSize < FilteredCount());
        PrevPageCommand = new RelayCommand(() => { Page--; ApplyFilterAndPage(); }, () => Page > 0);
        ToggleMonitorCommand = new RelayCommand(param => ToggleMonitor(param as ApplicationCatalogEntryViewModel));

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Refresh();
    }

    private int FilteredCount() => Filter(_allEntries).Count;

    private void Refresh()
    {
        if (string.IsNullOrEmpty(_catalogPath) || !File.Exists(_catalogPath))
        {
            TotalsText = "No application_catalog.json found yet — the endpoint writes this roughly every 20 seconds once running.";
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(_catalogPath));
            var root = doc.RootElement;
            var entries = new List<ApplicationCatalogEntryViewModel>();
            if (root.TryGetProperty("applications", out var apps) && apps.ValueKind == JsonValueKind.Array)
            {
                foreach (var app in apps.EnumerateArray())
                {
                    var exe = GetString(app, "executable");
                    if (string.IsNullOrEmpty(exe)) continue;
                    entries.Add(new ApplicationCatalogEntryViewModel
                    {
                        Executable = exe,
                        DisplayName = GetString(app, "display_name") is { Length: > 0 } dn ? dn : exe,
                        Path = GetString(app, "path") ?? "",
                        Publisher = GetString(app, "publisher") ?? "",
                        SignatureStatus = GetString(app, "signature_status") ?? "unavailable",
                        Installed = GetBool(app, "installed"),
                        Running = GetBool(app, "running"),
                        PidCount = (int)(GetLong(app, "pid_count") ?? 0),
                        Monitored = _watchlist.IsApplied(exe),
                        Busy = _watchlist.IsPending(exe)
                    });
                }
            }
            _allEntries = entries.OrderByDescending(e => e.Running).ThenBy(e => e.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();

            var totalDiscovered = GetLong(root, "total_discovered") ?? entries.Count;
            var totalRunning = GetLong(root, "total_running") ?? entries.Count(e => e.Running);
            var totalMonitored = GetLong(root, "total_monitored") ?? entries.Count(e => e.Monitored);
            TotalsText = $"{totalDiscovered:N0} discovered, {totalRunning:N0} running, {totalMonitored:N0} actively monitored";

            if (root.TryGetProperty("generated_at_ms", out var genEl) && genEl.TryGetInt64(out var genMs))
            {
                _generatedAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(genMs).UtcDateTime;
                var age = (DateTime.UtcNow - _generatedAtUtc.Value).TotalSeconds;
                FreshnessText = age < 40 ? $"Refreshed {age:0}s ago" : $"Stale — last refreshed {age / 60:0.0} min ago (endpoint may not be running)";
            }

            ApplyFilterAndPage();
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            TotalsText = $"Could not read application_catalog.json: {ex.Message}";
        }
    }

    private List<ApplicationCatalogEntryViewModel> Filter(List<ApplicationCatalogEntryViewModel> source)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return source;
        var needle = FilterText.Trim();
        return source.Where(e =>
            e.Executable.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
            e.DisplayName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
            e.Publisher.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
            e.Path.Contains(needle, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void ApplyFilterAndPage()
    {
        var filtered = Filter(_allEntries);
        var maxPage = Math.Max(0, (filtered.Count - 1) / PageSize);
        if (Page > maxPage) Page = maxPage;

        PageRows.Clear();
        foreach (var e in filtered.Skip(Page * PageSize).Take(PageSize)) PageRows.Add(e);

        PageText = filtered.Count == 0 ? "No matches" : $"Page {Page + 1} of {maxPage + 1} ({filtered.Count:N0} matching)";
        NextPageCommand.RaiseCanExecuteChanged();
        PrevPageCommand.RaiseCanExecuteChanged();
    }

    private async void ToggleMonitor(ApplicationCatalogEntryViewModel? entry)
    {
        if (entry is null || entry.Busy) return;
        entry.Busy = true;
        entry.ErrorText = "";
        var wantWatched = !entry.Monitored;
        var (ok, message) = await _watchlist.SetWatchedAsync(entry.Executable, wantWatched);
        if (!ok)
        {
            entry.Busy = false;
            entry.ErrorText = message;
        }
        else
        {
            entry.Monitored = wantWatched;
            entry.Busy = false;
        }
        // Success remains pending until the native watchlist_state.json acknowledgement
        // contains the requested membership. Refresh() then commits Monitored.
    }

    private static string? GetString(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static bool GetBool(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.True;
    private static long? GetLong(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : null;
}
