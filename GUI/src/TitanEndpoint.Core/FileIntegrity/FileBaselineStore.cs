using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.Core.FileIntegrity;

public sealed class FileBaselineEntry
{
    public required string NormalizedPath { get; init; }
    public required string Sha256 { get; init; }
    public string? FileIdentity { get; init; }
    public long SizeBytes { get; init; }
    public DateTime LastWriteUtc { get; init; }
    public DateTime ApprovedAtUtc { get; init; }
}

public enum BaselineComparisonState { NoBaseline, Unchanged, Changed, FileReplaced }

/// <summary>
/// Durable, authenticated per-user storage for manually approved File-page baselines.
/// The HMAC key is protected with Windows DPAPI and the evidence file is replaced atomically.
/// A corrupt or modified store is reported to the caller and is never treated as an empty store.
/// </summary>
public sealed class FileBaselineStore
{
    private sealed class StoreEnvelope
    {
        public int SchemaVersion { get; init; } = 2;
        public List<FileBaselineEntry> Entries { get; init; } = new();
        public string HmacSha256 { get; init; } = "";
    }

    private readonly string _storeDirectory;
    private string StorePath => Path.Combine(_storeDirectory, "file_baselines.json");
    private string KeyPath => Path.Combine(_storeDirectory, "file_baselines.key.dpapi");
    private static readonly JsonSerializerOptions PrettyOptions = new() { WriteIndented = true };

    private Dictionary<string, FileBaselineEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private bool _loaded;

    public string? LastError { get; private set; }
    public string IntegrityStatus { get; private set; } = "Not loaded";

    public FileBaselineStore(string? storeDirectory = null)
    {
        _storeDirectory = storeDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TitanEndpoint");
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        LastError = null;

        if (!File.Exists(StorePath))
        {
            IntegrityStatus = "No baseline store exists yet";
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(StorePath));
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                var legacy = document.RootElement.Deserialize<List<FileBaselineEntry>>(PrettyOptions) ?? new();
                _entries = ToDictionary(legacy);
                IntegrityStatus = "Legacy unsigned store loaded; it will be protected on the next approved save";
                return;
            }

            var envelope = document.RootElement.Deserialize<StoreEnvelope>(PrettyOptions)
                           ?? throw new JsonException("The baseline envelope is empty.");
            if (envelope.SchemaVersion != 2)
                throw new JsonException($"Unsupported baseline schema version {envelope.SchemaVersion}.");

            var key = LoadOrCreateKey(createIfMissing: false)
                      ?? throw new CryptographicException("The DPAPI integrity key is missing or unreadable.");
            var expected = ComputeHmac(key, envelope.Entries);
            byte[] supplied;
            try { supplied = Convert.FromHexString(envelope.HmacSha256); }
            catch (FormatException) { throw new CryptographicException("The baseline HMAC is malformed."); }
            if (!CryptographicOperations.FixedTimeEquals(expected, supplied))
                throw new CryptographicException("Baseline integrity verification failed.");

            _entries = ToDictionary(envelope.Entries);
            IntegrityStatus = "Integrity verified (DPAPI-protected HMAC)";
        }
        catch (Exception ex) when (ex is IOException or JsonException or CryptographicException or UnauthorizedAccessException)
        {
            LastError = $"Baseline store cannot be trusted: {ex.Message}";
            IntegrityStatus = "Integrity failure";
            _entries = new(StringComparer.OrdinalIgnoreCase);
        }
    }

    public FileBaselineEntry? Find(string path)
    {
        EnsureLoaded();
        return LastError is null ? _entries.GetValueOrDefault(Normalize(path)) : null;
    }

    public void Approve(string path, string sha256, long sizeBytes, DateTime lastWriteUtc)
    {
        EnsureLoaded();
        if (LastError is not null)
            throw new InvalidOperationException("Repair or remove the untrusted baseline store before approving a new baseline.");

        var normalized = Normalize(path);
        _entries[normalized] = new FileBaselineEntry
        {
            NormalizedPath = normalized,
            Sha256 = sha256,
            FileIdentity = TryGetFileIdentity(path),
            SizeBytes = sizeBytes,
            LastWriteUtc = lastWriteUtc,
            ApprovedAtUtc = DateTime.UtcNow
        };
        Save();
    }

    public BaselineComparisonState Compare(string path, string currentSha256)
    {
        var baseline = Find(path);
        if (baseline is null) return BaselineComparisonState.NoBaseline;
        var currentIdentity = TryGetFileIdentity(path);
        if (!string.IsNullOrEmpty(baseline.FileIdentity) && !string.IsNullOrEmpty(currentIdentity) &&
            !string.Equals(baseline.FileIdentity, currentIdentity, StringComparison.Ordinal))
            return BaselineComparisonState.FileReplaced;
        return string.Equals(baseline.Sha256, currentSha256, StringComparison.OrdinalIgnoreCase)
            ? BaselineComparisonState.Unchanged
            : BaselineComparisonState.Changed;
    }

    private static Dictionary<string, FileBaselineEntry> ToDictionary(IEnumerable<FileBaselineEntry> entries) =>
        entries.Where(e => !string.IsNullOrWhiteSpace(e.NormalizedPath))
            .GroupBy(e => e.NormalizedPath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(e => e.ApprovedAtUtc).First(), StringComparer.OrdinalIgnoreCase);

    private static string Normalize(string path)
    {
        try { return Path.GetFullPath(path).TrimEnd('\\').ToLowerInvariant(); }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        { return path.ToLowerInvariant(); }
    }

    private void Save()
    {
        Directory.CreateDirectory(_storeDirectory);
        var key = LoadOrCreateKey(createIfMissing: true)
                  ?? throw new CryptographicException("Windows DPAPI could not protect the baseline integrity key.");
        var entries = _entries.Values.OrderBy(e => e.NormalizedPath, StringComparer.OrdinalIgnoreCase).ToList();
        var envelope = new StoreEnvelope
        {
            Entries = entries,
            HmacSha256 = Convert.ToHexString(ComputeHmac(key, entries)).ToLowerInvariant()
        };
        DurableReplace(StorePath, JsonSerializer.SerializeToUtf8Bytes(envelope, PrettyOptions));
        LastError = null;
        IntegrityStatus = "Integrity verified (DPAPI-protected HMAC)";
    }

    private static byte[] ComputeHmac(byte[] key, List<FileBaselineEntry> entries)
    {
        var canonical = JsonSerializer.SerializeToUtf8Bytes(entries);
        return HMACSHA256.HashData(key, canonical);
    }

    private byte[]? LoadOrCreateKey(bool createIfMissing)
    {
        if (File.Exists(KeyPath))
            return DpapiUnprotect.TryUnprotectBytes(File.ReadAllBytes(KeyPath));
        if (!createIfMissing) return null;

        var key = RandomNumberGenerator.GetBytes(32);
        var protectedKey = DpapiUnprotect.TryProtect(key);
        if (protectedKey is null) return null;
        DurableReplace(KeyPath, protectedKey);
        return key;
    }

    private static void DurableReplace(string target, byte[] bytes)
    {
        var temporary = target + ".tmp";
        var backup = target + ".bak";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write,
                   FileShare.None, 16 * 1024, FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        if (File.Exists(target)) File.Replace(temporary, target, backup, ignoreMetadataErrors: true);
        else File.Move(temporary, target);
    }

    private static string? TryGetFileIdentity(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(handle, out var info)) return null;
            return $"{info.VolumeSerialNumber:x8}:{info.FileIndexHigh:x8}{info.FileIndexLow:x8}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile, out ByHandleFileInformation lpFileInformation);
}
