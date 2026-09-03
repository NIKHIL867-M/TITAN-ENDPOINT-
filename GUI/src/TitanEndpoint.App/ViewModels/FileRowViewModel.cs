using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class FileRowViewModel : IActionableRow
{
    public string Time { get; init; } = "";
    public string Category { get; init; } = "";
    public string Operation { get; init; } = "";
    public string Path { get; init; } = "";
    public string Process { get; init; } = "";
    public long Pid { get; init; }
    public string HashStatus { get; init; } = "";

    /// <summary>For RowActionsViewModel: "Stop" on a File row stops the process that touched the
    /// file (Process/Pid), not the file itself -- a file has no process to stop. "Open Location"
    /// correctly uses Path (the file), not this.</summary>
    public string DisplayName => string.IsNullOrEmpty(Process) ? (Pid > 0 ? $"pid {Pid}" : "file event") : Process;

    public static FileRowViewModel From(JsonRecord r)
    {
        var type = r.GetString("type");
        var isTemp = type is not null && type.StartsWith("temp_", StringComparison.OrdinalIgnoreCase);
        return new FileRowViewModel
        {
            Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
            Category = isTemp ? "Temporary" : "Normal",
            Operation = r.GetString("action") ?? r.GetString("target_action") ?? type ?? "event",
            Path = r.GetString("path") ?? r.GetString("target_path") ?? r.GetString("temp_path") ?? "",
            Process = r.GetString("process") ?? r.GetString("creator") ?? "",
            Pid = r.GetLong("pid") ?? r.GetLong("creator_pid") ?? 0,
            HashStatus = r.GetString("hash_status") ?? (r.GetBool("content_changed") == true ? "Content changed" : "")
        };
    }
}
