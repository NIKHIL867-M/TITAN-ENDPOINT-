using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class PortViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<PortRowViewModel> Rows { get; } = new();
    /// <summary>FORU.TXT 0.6: search must filter the visible view only -- never the underlying
    /// Rows collection itself, which ReconcileDeviceSessions and ActiveDevices bookkeeping depend
    /// on seeing in full regardless of what the operator is currently searching for.</summary>
    public ICollectionView RowsView { get; }
    public ObservableCollection<UsbDeviceCardViewModel> ActiveDevices { get; } = new();
    public RowActionsViewModel RowActions { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private string _activeSessionsText = "Unavailable";
    public string ActiveSessionsText { get => _activeSessionsText; private set => SetField(ref _activeSessionsText, value); }

    private string _connectionNotificationText = "";
    public string ConnectionNotificationText { get => _connectionNotificationText; private set => SetField(ref _connectionNotificationText, value); }

    private bool _hasConnectionNotification;
    public bool HasConnectionNotification { get => _hasConnectionNotification; private set => SetField(ref _hasConnectionNotification, value); }

    public RelayCommand DismissNotificationCommand { get; }

    private readonly IncrementalRowSync<PortRowViewModel> _sync;
    private readonly DispatcherTimer _timer;
    private readonly HashSet<string> _processedGenerations = new(StringComparer.OrdinalIgnoreCase);

    public PortViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Port, "Physical port and USB device activity");
        DismissNotificationCommand = new RelayCommand(() => HasConnectionNotification = false);
        // control_audit records (e.g. a SetPersistence toggle via the IPC control channel) are real,
        // legitimate accountability data -- still fully retained in the raw JSONL on disk -- but they
        // are not device activity and don't belong mixed into a grid titled "Port/USB events" with no
        // context beyond a raw-JSON fallback Detail string. Found live: a brief Start/Stop with zero
        // real device arrivals showed 5 rows that were entirely SetPersistence audit entries from
        // earlier sessions, which would read as confusing clutter to an operator looking for device
        // activity specifically.
        _sync = new IncrementalRowSync<PortRowViewModel>(Rows, maxRows: 2000, PortRowViewModel.From,
            filter: r => !r.IsCollectorHealth && !r.Is("type", "control_audit"));
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void Tick()
    {
        var tailer = Header.State.Tailer;
        _sync.Sync(tailer.Records.Snapshot());
        ReconcileDeviceSessions();

        SummaryText = tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : Rows.Count == 0
                ? "No USB device activity observed in this session."
                : $"{Rows.Count:N0} device events in view (bounded).";

        if (tailer.LastHealth is not null)
        {
            var active = tailer.LastHealth.GetLong("active_sessions");
            ActiveSessionsText = active is null ? "Unavailable" : active.Value.ToString("N0");
        }
        else
        {
            ActiveSessionsText = "Unavailable";
        }
    }

    private void ReconcileDeviceSessions()
    {
        foreach (var row in Rows)
        {
            if (!_processedGenerations.Add(row.GenerationKey)) continue;
            if (row.IsSessionEnd)
            {
                var existing = ActiveDevices.FirstOrDefault(d =>
                    string.Equals(d.SessionId, row.SessionId, StringComparison.OrdinalIgnoreCase));
                if (existing is not null) ActiveDevices.Remove(existing);
                continue;
            }
            if (!row.IsArrival || string.IsNullOrWhiteSpace(row.SessionId)) continue;

            if (ActiveDevices.Any(d => string.Equals(d.SessionId, row.SessionId, StringComparison.OrdinalIgnoreCase)))
                continue;
            ActiveDevices.Add(new UsbDeviceCardViewModel
            {
                SessionId = row.SessionId,
                Device = string.IsNullOrWhiteSpace(row.Device) ? "Unnamed USB device" : row.Device,
                Manufacturer = row.Manufacturer,
                VidPid = row.VidPid,
                MountPoint = row.MountPoint,
                ConnectedAt = row.Time,
                Kind = row.EventType == "USB_HID_KEYBOARD_ARRIVED" ? "USB HID keyboard" : "USB storage/device"
            });
            while (ActiveDevices.Count > 20) ActiveDevices.RemoveAt(0);

            if (!row.IsHistorical)
            {
                ConnectionNotificationText = $"Connected: {(string.IsNullOrWhiteSpace(row.Device) ? "USB device" : row.Device)} " +
                                             $"({row.VidPid}) at {row.Time}";
                HasConnectionNotification = true;
            }
        }
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not PortRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.EventType.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Device.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.VidPid.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.MountPoint.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Manufacturer.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Detail.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }
}
