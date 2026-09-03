using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One row of the Start All / Stop All lifecycle dialog. Supports per-row retry,
/// details and copy-error actions (FORU.TXT section 3.7).</summary>
public sealed class StartAllRowViewModel : ViewModelBase
{
    public string Name { get; }

    private string _status = "Pending";
    public string Status
    {
        get => _status;
        set
        {
            if (SetField(ref _status, value))
            {
                OnPropertyChanged(nameof(HasFailed));
                RetryCommand.RaiseCanExecuteChanged();
            }
        }
    }

    private string _detailText = "";
    public string DetailText { get => _detailText; set => SetField(ref _detailText, value); }

    public bool HasFailed => Status.StartsWith("Failed", StringComparison.Ordinal);

    public RelayCommand RetryCommand { get; }
    public RelayCommand CopyErrorCommand { get; }
    public RelayCommand DetailsCommand { get; }

    public StartAllRowViewModel(string name, Func<Task>? retryAction = null)
    {
        Name = name;
        RetryCommand = new RelayCommand(async () => { if (retryAction is not null) await retryAction(); }, () => HasFailed && retryAction is not null);
        CopyErrorCommand = new RelayCommand(() =>
        {
            try { System.Windows.Clipboard.SetText($"{Name}: {Status}\n{DetailText}"); }
            catch (System.Runtime.InteropServices.COMException) { /* clipboard busy - best effort */ }
        });
        DetailsCommand = new RelayCommand(() =>
            System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow, string.IsNullOrEmpty(DetailText) ? Status : DetailText, $"{Name} — Details",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information));
    }
}
