using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One row of the full discovered/installed/running application catalogue (FORU.TXT
/// section 9.2-9.3) — sourced from config\application_catalog.json, written periodically by the
/// native endpoint's ApplicationDiscovery::Discover() (registry + running-process snapshot,
/// never launches anything).</summary>
public sealed class ApplicationCatalogEntryViewModel : ViewModelBase
{
    public string Executable { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Path { get; init; } = "";
    public string Publisher { get; init; } = "";
    public string SignatureStatus { get; init; } = "unavailable";
    public bool Installed { get; init; }
    public bool Running { get; init; }
    public int PidCount { get; init; }

    private bool _monitored;
    public bool Monitored { get => _monitored; set => SetField(ref _monitored, value); }

    public string StateText => Installed && Running ? "Installed, Running"
        : Running ? "Running" : Installed ? "Installed" : "Discovered";

    private bool _busy;
    public bool Busy { get => _busy; set => SetField(ref _busy, value); }

    private string _errorText = "";
    public string ErrorText { get => _errorText; set => SetField(ref _errorText, value); }
}
