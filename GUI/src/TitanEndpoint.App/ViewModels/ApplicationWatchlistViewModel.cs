using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.App.ViewModels;

public sealed class WatchlistEntryViewModel : ViewModelBase
{
    public string ExeName { get; init; } = "";

    private bool _isWatched;
    public bool IsWatched { get => _isWatched; set => SetField(ref _isWatched, value); }

    private bool _appliedByCollector;
    public bool AppliedByCollector { get => _appliedByCollector; set => SetField(ref _appliedByCollector, value); }
}

/// <summary>
/// Revision-bound live control for the Application endpoint watchlist. The effective list is
/// read from GetStatus and changed only through authenticated SetWatchlist IPC. The historical
/// watchlist.txt polling path can remain native-side for backward compatibility, but this GUI no
/// longer writes or trusts it as live collector state.
/// </summary>
public sealed class ApplicationWatchlistViewModel : ViewModelBase
{
    public const int Capacity = 20;
    public ObservableCollection<WatchlistEntryViewModel> Entries { get; } = new();

    private string _newAppName = "";
    public string NewAppName
    {
        get => _newAppName;
        set
        {
            if (SetField(ref _newAppName, value)) AddCommand.RaiseCanExecuteChanged();
        }
    }

    private string _statusText = "Connecting to the Application endpoint control channel...";
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }

    private string _capacityText = $"0 / {Capacity}";
    public string CapacityText { get => _capacityText; private set => SetField(ref _capacityText, value); }

    private string _addErrorText = "";
    public string AddErrorText { get => _addErrorText; private set => SetField(ref _addErrorText, value); }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (!SetField(ref _isBusy, value)) return;
            AddCommand.RaiseCanExecuteChanged();
            RemoveCommand.RaiseCanExecuteChanged();
        }
    }

    public RelayCommand AddCommand { get; }
    public RelayCommand RemoveCommand { get; }

    private readonly EndpointControlClient? _controlClient;
    private readonly DispatcherTimer _timer;
    private bool _refreshBusy;
    private string? _nativeSessionId;
    private long _nativeRevision;
    private long _watchlistRevision;

    public ApplicationWatchlistViewModel(EndpointDefinition applicationDefinition)
    {
        if (applicationDefinition.ManifestControlChannelImplemented &&
            !string.IsNullOrWhiteSpace(applicationDefinition.ManifestControlChannelName))
        {
            _controlClient = new EndpointControlClient(applicationDefinition.ManifestControlChannelName);
        }

        AddCommand = new RelayCommand(AddNew,
            () => !IsBusy && !string.IsNullOrWhiteSpace(NewAppName) && Entries.Count < Capacity);
        RemoveCommand = new RelayCommand(parameter => Remove(parameter as WatchlistEntryViewModel),
            _ => !IsBusy);

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _timer.Tick += async (_, _) => await RefreshFromCollectorAsync();
        _timer.Start();
        _ = RefreshFromCollectorAsync();
    }

    private async Task RefreshFromCollectorAsync()
    {
        if (_refreshBusy || IsBusy) return;
        if (_controlClient is null)
        {
            StatusText = "Application control IPC is not configured in runtime-manifest.json.";
            return;
        }

        _refreshBusy = true;
        try
        {
            var response = await _controlClient.SendAsync("GetStatus", timeout: TimeSpan.FromSeconds(2));
            if (!response.Reachable || !response.Ok)
            {
                StatusText = response.Reachable
                    ? $"Application endpoint rejected status: {response.Error ?? "unknown error"}."
                    : "Application endpoint is not reachable. Start it before changing the live watchlist.";
                return;
            }

            ApplyStatus(response.Root);
        }
        finally
        {
            _refreshBusy = false;
        }
    }

    private void ApplyStatus(JsonElement root)
    {
        _nativeSessionId = root.TryGetProperty("session_id", out var session) &&
                           session.ValueKind == JsonValueKind.String
            ? session.GetString()
            : null;
        _nativeRevision = root.TryGetProperty("revision", out var revision) && revision.TryGetInt64(out var rv)
            ? rv
            : 0;
        _watchlistRevision = root.TryGetProperty("watchlist_revision", out var watchRevision) &&
                             watchRevision.TryGetInt64(out var wr)
            ? wr
            : 0;

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("watchlist", out var watchlist) && watchlist.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in watchlist.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                    names.Add(item.GetString()!);
        }

        foreach (var old in Entries.Where(entry => !names.Contains(entry.ExeName)).ToList()) Entries.Remove(old);
        foreach (var name in names.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            var entry = Entries.FirstOrDefault(item =>
                string.Equals(item.ExeName, name, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                entry = new WatchlistEntryViewModel { ExeName = name };
                Entries.Add(entry);
            }
            entry.IsWatched = true;
            entry.AppliedByCollector = true;
        }

        CapacityText = $"{Entries.Count} / {Capacity}";
        AddCommand.RaiseCanExecuteChanged();
        StatusText = $"Applied by native session {_nativeSessionId ?? "unknown"}; control revision {_nativeRevision}, watchlist revision {_watchlistRevision}.";
    }

    private async void AddNew()
    {
        AddErrorText = "";
        var name = NormalizeExeName(NewAppName);
        if (name is null)
        {
            AddErrorText = "Enter a valid executable filename ending in .exe.";
            return;
        }
        if (Entries.Any(entry => string.Equals(entry.ExeName, name, StringComparison.OrdinalIgnoreCase)))
        {
            AddErrorText = $"{name} is already on the native watchlist.";
            return;
        }
        if (Entries.Count >= Capacity)
        {
            AddErrorText = $"The native watchlist is limited to {Capacity} applications.";
            return;
        }

        var desired = Entries.Select(entry => entry.ExeName).Append(name).ToArray();
        if (await ApplyDesiredAsync(desired)) NewAppName = "";
    }

    private async void Remove(WatchlistEntryViewModel? entry)
    {
        if (entry is null) return;
        AddErrorText = "";
        var desired = Entries.Where(item => !ReferenceEquals(item, entry))
            .Select(item => item.ExeName).ToArray();
        await ApplyDesiredAsync(desired);
    }

    private async Task<bool> ApplyDesiredAsync(IReadOnlyCollection<string> desired)
    {
        if (_controlClient is null)
        {
            AddErrorText = "Application control IPC is not configured.";
            return false;
        }

        IsBusy = true;
        StatusText = "Waiting for revision-bound native acknowledgement...";
        try
        {
            var response = await _controlClient.SendRevisionedAsync("SetWatchlist",
                new { applications = desired.ToArray() }, TimeSpan.FromSeconds(5));
            if (!response.Reachable || !response.Ok)
            {
                AddErrorText = response.Reachable
                    ? $"Collector rejected the watchlist: {response.Error ?? "unknown error"}"
                    : $"Application control channel is unreachable: {response.TransportError}";
                StatusText = "No change was assumed; collector acknowledgement is required.";
                return false;
            }

            ApplyStatus(response.Root);
            if (!response.Root.TryGetProperty("accepted_watchlist_revision", out var accepted) ||
                !accepted.TryGetInt64(out var acceptedRevision) || acceptedRevision != _watchlistRevision)
            {
                AddErrorText = "The collector replied without the exact accepted watchlist revision.";
                StatusText = "Change is not trusted until a matching revision is observed.";
                return false;
            }
            return true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static string? NormalizeExeName(string raw)
    {
        var value = raw.Trim().ToLowerInvariant();
        if (!value.EndsWith(".exe", StringComparison.Ordinal)) value += ".exe";
        if (value.Length is < 5 or > 260 || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            value.Contains('\\') || value.Contains('/')) return null;
        return value;
    }

    public bool IsApplied(string executable) => Entries.Any(entry =>
        entry.AppliedByCollector && string.Equals(entry.ExeName, executable, StringComparison.OrdinalIgnoreCase));

    public bool IsPending(string executable) => IsBusy;

    public async Task<(bool Ok, string Message)> SetWatchedAsync(string executable, bool watched)
    {
        var normalized = NormalizeExeName(executable);
        if (normalized is null) return (false, "Invalid executable name.");
        var desired = Entries.Select(entry => entry.ExeName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (watched) desired.Add(normalized); else desired.Remove(normalized);
        if (desired.Count > Capacity) return (false, $"The native watchlist is limited to {Capacity} applications.");
        var ok = await ApplyDesiredAsync(desired);
        return (ok, ok ? "Native collector acknowledged the revision." : AddErrorText);
    }
}
