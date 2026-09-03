using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Windows;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One row in the "Received Reports" list -- kept minimal, purely for display.</summary>
public sealed class ReceivedReportRowViewModel
{
    public string TimeText { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public string BodyPreview { get; init; } = "";
    public string FullBody { get; init; } = "";
    public RelayCommand ViewFullCommand { get; }

    public ReceivedReportRowViewModel()
    {
        ViewFullCommand = new RelayCommand(() =>
            MessageBox.Show(Application.Current?.MainWindow, FullBody, $"Report received {TimeText} from {RemoteAddress}",
                MessageBoxButton.OK, MessageBoxImage.Information));
    }
}

/// <summary>Round 24 (VISHNU.TXT / Santosh: "from the Correlator logs to the STIX format which
/// OpenCTI wanted... add a button for converting all these correlated logs JSON file into that
/// particular format"). One-shot, on-demand, purely local conversion: reads the Correlator's own
/// correlated_events.json and writes a STIX 2.1 Bundle file next to it -- no network call, since
/// there is nowhere to send it yet (OpenCTI is being set up on a separate machine first, per the
/// plan in TITAN_OPENCTI_INTEGRATION_PLAN.txt). Once that instance exists, the bundle file this page
/// produces can be imported into it by hand; a live push connector is a later, separate step.</summary>
public sealed class StixExportViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }

    private readonly string _correlatedEventsPath;
    private readonly string _outputDir;

    private string _sourceStatusText = "Checking for correlated_events.json...";
    public string SourceStatusText { get => _sourceStatusText; private set => SetField(ref _sourceStatusText, value); }

    private string _resultText = "No conversion run yet this session.";
    public string ResultText { get => _resultText; private set => SetField(ref _resultText, value); }

    private bool _lastRunSucceeded;
    public bool LastRunSucceeded { get => _lastRunSucceeded; private set => SetField(ref _lastRunSucceeded, value); }

    public RelayCommand ConvertCommand { get; }
    public RelayCommand OpenOutputFolderCommand { get; }
    public RelayCommand RefreshStatusCommand { get; }

    // ================= Santosh, 2026-08-27: "create a 2-way port in this application to send and
    // receive information." Send half: POST the last converted bundle to wherever the user points
    // it (their OpenCTI laptop's own receiver, once that exists, or any test endpoint meanwhile).
    // Receive half: TitanReportListener, an embedded HTTP listener the other side can push a report
    // back to whenever it's ready. Both share one token so neither side talks to the wrong thing. =================
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(15) };
    private TitanReportListener? _listener;
    private string? _lastBundleJson;

    private string _targetUrl = "";
    public string TargetUrl { get => _targetUrl; set => SetField(ref _targetUrl, value); }

    private string _sharedToken = Guid.NewGuid().ToString("N");
    public string SharedToken
    {
        get => _sharedToken;
        set { if (SetField(ref _sharedToken, value) && _listener is not null) _listener.SharedToken = value; }
    }

    private string _sendResultText = "";
    public string SendResultText { get => _sendResultText; private set => SetField(ref _sendResultText, value); }

    private string _listenAddressText = "Starting receiver...";
    public string ListenAddressText { get => _listenAddressText; private set => SetField(ref _listenAddressText, value); }

    public ObservableCollection<ReceivedReportRowViewModel> ReceivedReports { get; } = new();

    public RelayCommand SendCommand { get; }

    public StixExportViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Correlator,
            "Converts the Correlator's own correlated_events.json into a STIX 2.1 bundle for OpenCTI or any other STIX consumer");

        var correlatorLogDir = App.Fleet.Get(EndpointId.Correlator).Definition.LogDirectory;
        _correlatedEventsPath = Path.Combine(correlatorLogDir, "correlated_events.json");
        _outputDir = Path.Combine(correlatorLogDir, "stix_export");

        ConvertCommand = new RelayCommand(RunConversion);
        OpenOutputFolderCommand = new RelayCommand(OpenOutputFolder, () => Directory.Exists(_outputDir));
        RefreshStatusCommand = new RelayCommand(RefreshStatus);
        SendCommand = new RelayCommand(async () => await SendAsync(), () => !string.IsNullOrWhiteSpace(TargetUrl) && _lastBundleJson is not null);

        RefreshStatus();

        // Santosh, 2026-08-27: "the STIX page is not opening." Whatever the exact cause, nothing in
        // this brand-new receive-listener setup should ever be able to take the whole page down with
        // it -- the entire block is defensive on purpose, not just the Start() call, so a page that
        // used to work before this feature was added can never stop opening because of it.
        try
        {
            _listener = new TitanReportListener(8766) { SharedToken = _sharedToken };
            _listener.ReportReceived += OnReportReceived;
            _listener.ListenerError += msg => Application.Current?.Dispatcher.Invoke(() => SendResultText = $"Receiver error: {msg}");
            _listener.Start();
            var host = _listener.IsListeningOnAllInterfaces ? TitanReportListener.GetBestLocalIPv4() : "127.0.0.1 (loopback only)";
            ListenAddressText = _listener.IsListeningOnAllInterfaces
                ? $"http://{host}:{_listener.Port}/titan/report  (reachable from other machines on this network)"
                : $"http://{host}:{_listener.Port}/titan/report  (loopback only -- run TITAN as Administrator for other machines to reach this)";
        }
        catch (Exception ex)
        {
            ListenAddressText = $"Receiver failed to start: {ex.Message}";
        }
    }

    private void OnReportReceived(ReceivedReport report)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var preview = report.Body.Length > 300 ? report.Body[..300] + "..." : report.Body;
            ReceivedReports.Insert(0, new ReceivedReportRowViewModel
            {
                TimeText = report.ReceivedAtUtc.ToLocalTime().ToString("HH:mm:ss"),
                RemoteAddress = report.RemoteAddress,
                BodyPreview = preview,
                FullBody = report.Body
            });
        });
    }

    private async Task SendAsync()
    {
        if (_lastBundleJson is null) { SendResultText = "Nothing to send yet -- run Convert to STIX first."; return; }
        if (string.IsNullOrWhiteSpace(TargetUrl)) { SendResultText = "Enter a target address first."; return; }
        SendResultText = $"Sending to {TargetUrl}...";
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, TargetUrl)
            {
                Content = new StringContent(_lastBundleJson, Encoding.UTF8, "application/json")
            };
            request.Headers.Add("X-Titan-Token", SharedToken);
            var response = await _httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();
            SendResultText = $"{(int)response.StatusCode} {response.ReasonPhrase} — {(responseBody.Length > 400 ? responseBody[..400] + "..." : responseBody)}";
        }
        catch (Exception ex)
        {
            SendResultText = $"Send failed: {ex.Message}";
        }
    }

    private void RefreshStatus()
    {
        if (!File.Exists(_correlatedEventsPath))
        {
            SourceStatusText = $"Waiting for the Correlator to write its first snapshot -- no file yet at {_correlatedEventsPath}";
            return;
        }
        var info = new FileInfo(_correlatedEventsPath);
        SourceStatusText = $"Source: {_correlatedEventsPath}  ({info.Length:N0} bytes, last written {info.LastWriteTime:HH:mm:ss})";
    }

    private void RunConversion()
    {
        RefreshStatus();
        var conversion = StixConverter.Convert(_correlatedEventsPath);
        if (!conversion.Success)
        {
            LastRunSucceeded = false;
            ResultText = conversion.ErrorMessage ?? "Conversion failed for an unknown reason.";
            return;
        }

        try
        {
            Directory.CreateDirectory(_outputDir);
            var fileName = $"titan_stix_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
            var outPath = Path.Combine(_outputDir, fileName);
            File.WriteAllText(outPath, conversion.BundleJson);

            LastRunSucceeded = true;
            _lastBundleJson = conversion.BundleJson;
            ResultText =
                $"Converted {conversion.IncidentsExported} of {conversion.IncidentsRead} correlated incident(s) into a STIX 2.1 bundle " +
                $"({conversion.ObservedDataCount} observed-data object(s); {conversion.Ipv4Count} IPv4 + {conversion.Ipv6Count} IPv6 address(es), " +
                $"{conversion.FileCount} file(s) [{conversion.FileWithHashCount} with a real SHA-256], {conversion.ProcessCount} process(es), " +
                $"{conversion.NetworkTrafficCount} network-traffic object(s), {conversion.UsbDeviceCount} USB device(s)).\n" +
                $"{conversion.IncidentsSkippedNoObservables} incident(s) skipped -- no exportable observable (e.g. process-only activity with no IP/file/hash).\n" +
                $"Written to: {outPath}";
        }
        catch (Exception ex)
        {
            LastRunSucceeded = false;
            ResultText = $"Conversion succeeded but writing the file failed: {ex.Message}";
        }
        OpenOutputFolderCommand.RaiseCanExecuteChanged();
        SendCommand.RaiseCanExecuteChanged();
    }

    private void OpenOutputFolder()
    {
        if (!Directory.Exists(_outputDir)) return;
        Process.Start(new ProcessStartInfo { FileName = _outputDir, UseShellExecute = true });
    }
}
