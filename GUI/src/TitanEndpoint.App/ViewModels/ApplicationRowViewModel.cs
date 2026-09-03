using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class ApplicationRowViewModel : IActionableRow
{
    public string Time { get; init; } = "";
    public string Category { get; init; } = "";
    public string Application { get; init; } = "";
    public string Action { get; init; } = "";
    public long Pid { get; init; }
    public string Path { get; init; } = "";

    // Real fields the native collector already emits for type:"network" watchlist events
    // (applog_monitor.cpp's periodic per-watched-PID TCP/UDP socket table scan) but the GUI
    // previously dropped entirely -- Santosh, 2026-08-04: "it even has to show ... what
    // particular application is doing inbound and outbound." Zero native changes needed; this
    // was already-captured data that just never reached the table.
    public string Protocol { get; init; } = "";
    public string LocalEndpoint { get; init; } = "";
    public string RemoteEndpoint { get; init; } = "";
    public string ConnectionState { get; init; } = "";

    /// <summary>Honest, coarse classification from the native socket-table snapshot alone --
    /// "Listening" when this app has bound a local port with no remote peer (event.action=="bind"),
    /// "Connected" when it has an active local+remote pair. This is NOT a packet-direction
    /// determination (the Network endpoint's own real capture computes that from real traffic);
    /// deliberately not labelled "Inbound"/"Outbound" here to avoid implying more precision than a
    /// point-in-time socket table actually gives.</summary>
    public string ConnectionSummary => Category != "network" ? ""
        : string.IsNullOrEmpty(RemoteEndpoint) ? $"Listening on {LocalEndpoint} ({Protocol})"
        : $"{LocalEndpoint} ↔ {RemoteEndpoint} ({Protocol}, {ConnectionState})";

    public string DisplayName => string.IsNullOrEmpty(Application) ? (Pid > 0 ? $"pid {Pid}" : "application event") : Application;

    public static ApplicationRowViewModel From(JsonRecord r) => new()
    {
        Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
        Category = r.GetString("type") ?? "event",
        Application = r.GetString("application") ?? "",
        Action = r.GetString("action") ?? "",
        Pid = r.GetLong("pid") ?? 0,
        Path = r.GetString("path") ?? "",
        Protocol = r.GetString("protocol") ?? "",
        LocalEndpoint = r.GetString("local_endpoint") ?? "",
        RemoteEndpoint = r.GetString("remote_endpoint") ?? "",
        ConnectionState = r.GetString("connection_state") ?? ""
    };
}
