namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// Minimal shape RowActionsViewModel needs from any endpoint's row type to offer
/// Open Location / Stop / Isolate — implemented by ProcessRowViewModel, FileRowViewModel,
/// ApplicationRowViewModel and PortRowViewModel so one shared action menu works identically
/// across every page rather than four separate re-implementations.
/// </summary>
public interface IActionableRow
{
    long Pid { get; }
    string Path { get; }
    string DisplayName { get; }
}
