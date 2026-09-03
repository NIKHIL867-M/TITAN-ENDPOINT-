using System.Windows;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// Backs the "Open File Location / Stop / Isolate" row context menu on any endpoint's event
/// table (Santosh, 2026-08-04: "if I click any log I should need to get some option like stop or
/// isolate or open in location"). One shared instance per page, driven by whichever row the
/// right-click happened on (passed as CommandParameter, not a page-wide "selected row" — a
/// context menu action always targets the row it was opened from).
///
/// Stop and Isolate are real, hard-to-reverse actions (kill a process; add a firewall rule), so
/// both go through an explicit confirmation dialog first, matching this app's existing
/// destructive-action-confirmation convention (Custom Rule wizard's kill_process/isolate_host
/// checkboxes). Open Location has no side effect and never confirms.
/// </summary>
public sealed class RowActionsViewModel : ViewModelBase
{
    private string _lastResultText = "";
    public string LastResultText { get => _lastResultText; private set => SetField(ref _lastResultText, value); }

    public RelayCommand OpenLocationCommand { get; }
    public RelayCommand StopCommand { get; }
    public RelayCommand IsolateCommand { get; }
    public RelayCommand RemoveIsolationCommand { get; }

    public RowActionsViewModel()
    {
        OpenLocationCommand = new RelayCommand(p => Run(p, row => RowActionService.OpenFileLocation(row.Path)));

        StopCommand = new RelayCommand(p => RunWithConfirmation(p,
            row => $"Stop \"{row.DisplayName}\" (pid {row.Pid})?\n\nThis terminates the process immediately.",
            row => RowActionService.StopProcess((int)row.Pid, row.DisplayName)));

        IsolateCommand = new RelayCommand(p => RunWithConfirmation(p,
            row => $"Isolate \"{row.DisplayName}\"?\n\nThis blocks ALL inbound and outbound network traffic for {row.Path} at the Windows Firewall until you remove the isolation.",
            row => RowActionService.IsolateProcess(row.Path, row.DisplayName)));

        RemoveIsolationCommand = new RelayCommand(p => Run(p, row => RowActionService.RemoveIsolation(row.Path, row.DisplayName)));
    }

    private void Run(object? parameter, Func<IActionableRow, (bool Ok, string Message)> action)
    {
        if (parameter is not IActionableRow row)
        {
            LastResultText = "No event was selected.";
            return;
        }
        var (ok, message) = action(row);
        LastResultText = message;
        if (!ok)
            MessageBox.Show(Application.Current?.MainWindow, message, "Action failed", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void RunWithConfirmation(object? parameter, Func<IActionableRow, string> confirmText,
        Func<IActionableRow, (bool Ok, string Message)> action)
    {
        if (parameter is not IActionableRow row)
        {
            LastResultText = "No event was selected.";
            return;
        }

        // Santosh, 2026-08-27: confirmed live that the no-owner MessageBox.Show overload can
        // return without ever creating a visible window at all (see round26 memory) -- for a
        // destructive-action confirmation specifically, that would mean this either silently
        // never confirms (safe, but the action just appears to do nothing) or, worse, resolves to
        // something other than the explicit No default without the user ever seeing the prompt.
        // Passing the main window as owner is the fix used everywhere else in this app.
        var confirmed = MessageBox.Show(Application.Current?.MainWindow, confirmText(row), "Confirm action",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
        if (!confirmed)
        {
            LastResultText = "Cancelled.";
            return;
        }

        var (ok, message) = action(row);
        LastResultText = message;
        if (!ok)
            MessageBox.Show(Application.Current?.MainWindow, message, "Action failed", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}
