using System.Text.Json;

namespace TitanEndpoint.Core.CustomRule;

/// <summary>
/// GUI-local acknowledgement state for alerts (FORU.TXT section 14.5: "Add bounded paging/
/// filtering and acknowledgement state without rewriting the original immutable alert
/// evidence"). Acknowledging an alert never touches CUSTOM RULE's own alerts.jsonl or its
/// signed evidence files — it's tracked entirely separately here, at
/// %LOCALAPPDATA%\TitanEndpoint\alert_acks.json, keyed by the alert's own stable "id" field.
/// </summary>
public sealed class AlertAckStore
{
    private static string StorePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TitanEndpoint", "alert_acks.json");

    private HashSet<string> _acked = new(StringComparer.Ordinal);
    private bool _loaded;

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (File.Exists(StorePath))
            {
                var ids = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(StorePath));
                if (ids is not null) _acked = new HashSet<string>(ids, StringComparer.Ordinal);
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            _acked = new(StringComparer.Ordinal);
        }
    }

    public bool IsAcknowledged(string alertId)
    {
        EnsureLoaded();
        return _acked.Contains(alertId);
    }

    public void Acknowledge(string alertId)
    {
        EnsureLoaded();
        if (!_acked.Add(alertId)) return;
        Save();
    }

    private void Save()
    {
        var dir = Path.GetDirectoryName(StorePath)!;
        Directory.CreateDirectory(dir);
        var temp = StorePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_acked.ToList()));
        File.Move(temp, StorePath, overwrite: true);
    }
}
