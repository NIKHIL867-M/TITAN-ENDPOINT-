using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

public sealed class ActivityItemViewModel
{
    public required DateTimeOffset TimeUtc { get; init; }
    public required string EndpointIcon { get; init; }
    public required string EndpointName { get; init; }
    public required string EventType { get; init; }
    public required string MainEntity { get; init; }
    public string TimeLocalText => TimeUtc.ToLocalTime().ToString("HH:mm:ss");

    /// <summary>Preserves a link back to the original source record (FORU.TXT 7.3: "preserve
    /// links to the original source record") — the raw JSON line this timeline entry summarizes.</summary>
    public string RawJson { get; init; } = "";

    public RelayCommand OpenEvidenceCommand => new(() =>
        System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow, RawJson, $"{EndpointName} — Original Evidence Record",
            System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information));
}
