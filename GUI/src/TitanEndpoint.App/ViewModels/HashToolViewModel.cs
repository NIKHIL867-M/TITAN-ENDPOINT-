using System.IO;
using System.Security.Cryptography;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.FileIntegrity;

namespace TitanEndpoint.App.ViewModels;

public sealed class HashToolViewModel : ViewModelBase
{
    private string _selectedPath = "";
    public string SelectedPath { get => _selectedPath; private set => SetField(ref _selectedPath, value); }

    private string _statusText = "No file selected.";
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }

    private string _hashResult = "";
    public string HashResult { get => _hashResult; private set => SetField(ref _hashResult, value); }

    private bool _isBusy;
    public bool IsBusy { get => _isBusy; private set => SetField(ref _isBusy, value); }

    private double _progress;
    public double Progress { get => _progress; private set => SetField(ref _progress, value); }

    /// <summary>FORU.TXT section 10.5: "a file-changed-during-hash check." Compares the file's
    /// size/last-write-time before and after hashing — if either changed mid-read, the resulting
    /// hash may not represent a single consistent snapshot of the file's content.</summary>
    private bool _wasUnstableDuringHash;
    public bool WasUnstableDuringHash { get => _wasUnstableDuringHash; private set => SetField(ref _wasUnstableDuringHash, value); }

    private string _baselineStateText = "No file hashed yet.";
    public string BaselineStateText { get => _baselineStateText; private set => SetField(ref _baselineStateText, value); }

    private bool _hasExistingBaseline;
    public bool HasExistingBaseline { get => _hasExistingBaseline; private set => SetField(ref _hasExistingBaseline, value); }

    public RelayCommand CancelCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand ApproveBaselineCommand { get; }

    private readonly FileBaselineStore _baselineStore = new();
    private CancellationTokenSource? _cts;
    private long _sizeAtHashTime;
    private DateTime _lastWriteAtHashTime;

    public HashToolViewModel()
    {
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsBusy);
        CopyCommand = new RelayCommand(() =>
        {
            if (!string.IsNullOrEmpty(HashResult))
                System.Windows.Clipboard.SetText(HashResult);
        }, () => !string.IsNullOrEmpty(HashResult));
        ApproveBaselineCommand = new RelayCommand(ApproveBaseline,
            () => !string.IsNullOrEmpty(HashResult) && !IsBusy && !WasUnstableDuringHash);
    }

    public async void HashFile(string path)
    {
        SelectedPath = path;
        HashResult = "";
        Progress = 0;
        WasUnstableDuringHash = false;
        BaselineStateText = "";
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        FileInfo info;
        try { info = new FileInfo(path); }
        catch (Exception ex)
        {
            StatusText = $"Cannot access file: {ex.Message}";
            return;
        }

        IsBusy = true;
        StatusText = $"Hashing {info.Length:N0} bytes...";
        var sw = System.Diagnostics.Stopwatch.StartNew();
        _sizeAtHashTime = info.Length;
        _lastWriteAtHashTime = info.LastWriteTimeUtc;

        try
        {
            var dispatcher = System.Windows.Application.Current.Dispatcher;
            var hash = await Task.Run(() => ComputeSha256(path, info.Length, token,
                p => dispatcher.BeginInvoke(() => Progress = p)), token);
            sw.Stop();
            HashResult = Convert.ToHexString(hash).ToLowerInvariant();

            // File-changed-during-hash check (10.5): re-stat and compare against the pre-hash
            // snapshot. A large file that's actively being written could otherwise produce a
            // hash matching neither its before- nor after-write content.
            FileInfo after;
            try { after = new FileInfo(path); }
            catch { after = info; }
            WasUnstableDuringHash = after.Length != _sizeAtHashTime || after.LastWriteTimeUtc != _lastWriteAtHashTime;

            StatusText = WasUnstableDuringHash
                ? $"Done in {sw.Elapsed.TotalSeconds:0.00}s, but the file changed size or timestamp WHILE hashing — this result may not reflect one consistent snapshot. Re-hash before trusting it."
                : $"Done in {sw.Elapsed.TotalSeconds:0.00}s — {info.Length:N0} bytes, modified {info.LastWriteTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";

            RefreshBaselineComparison(path);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Hashing cancelled.";
        }
        catch (Exception ex)
        {
            StatusText = $"Hashing failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RefreshBaselineComparison(string path)
    {
        var baseline = _baselineStore.Find(path);
        if (_baselineStore.LastError is not null)
        {
            HasExistingBaseline = false;
            BaselineStateText = _baselineStore.LastError;
            return;
        }
        HasExistingBaseline = baseline is not null;
        if (baseline is null)
        {
            BaselineStateText = "No approved baseline exists for this path yet.";
            return;
        }

        var state = _baselineStore.Compare(path, HashResult);
        BaselineStateText = state switch
        {
            BaselineComparisonState.Unchanged =>
                $"Unchanged — matches the baseline approved {baseline.ApprovedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}.",
            BaselineComparisonState.Changed =>
                $"Content changed. SHA-256 differs from the approved baseline ({baseline.ApprovedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}, was {baseline.SizeBytes:N0} bytes).",
            BaselineComparisonState.FileReplaced =>
                "The path now identifies a different file object than the approved baseline. Treat this as a replacement even if its bytes happen to match.",
            _ => "No approved baseline exists for this path yet."
        };
    }

    private void ApproveBaseline()
    {
        if (string.IsNullOrEmpty(HashResult) || WasUnstableDuringHash) return;

        var existing = _baselineStore.Find(SelectedPath);
        if (existing is not null)
        {
            var confirm = System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow,
                $"A baseline for this path was already approved on {existing.ApprovedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}. Replace it with the current hash?",
                "Replace Existing Baseline", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning);
            if (confirm != System.Windows.MessageBoxResult.Yes) return;
        }

        try
        {
            _baselineStore.Approve(SelectedPath, HashResult, _sizeAtHashTime, _lastWriteAtHashTime);
            RefreshBaselineComparison(SelectedPath);
            StatusText = $"Baseline saved. {_baselineStore.IntegrityStatus}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or CryptographicException)
        {
            StatusText = $"Baseline was not saved: {ex.Message}";
        }
    }

    private static byte[] ComputeSha256(string path, long totalLength, CancellationToken token, Action<double> onProgress)
    {
        using var sha = SHA256.Create();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        var buffer = new byte[1 << 20];
        long readTotal = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            token.ThrowIfCancellationRequested();
            sha.TransformBlock(buffer, 0, read, null, 0);
            readTotal += read;
            if (totalLength > 0) onProgress(Math.Min(1.0, readTotal / (double)totalLength));
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }
}
