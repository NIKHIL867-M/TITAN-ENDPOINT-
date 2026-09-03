using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class PortRowViewModel : IActionableRow
{
    public string Time { get; init; } = "";
    public string EventType { get; init; } = "";
    public string Device { get; init; } = "";
    public string VidPid { get; init; } = "";
    public string MountPoint { get; init; } = "";
    public string Detail { get; init; } = "";
    public string SessionId { get; init; } = "";
    public string Manufacturer { get; init; } = "";
    public bool IsArrival { get; init; }
    public bool IsSessionEnd { get; init; }
    public bool IsHistorical { get; init; }
    public string GenerationKey { get; init; } = "";

    /// <summary>A USB device has no OS process to stop -- only Open Location (the drive's mount
    /// point, when it has one) is meaningful here; RowActionsViewModel disables Stop/Isolate for a
    /// zero Pid with a clear reason rather than hiding them inconsistently per page.</summary>
    long IActionableRow.Pid => 0;
    string IActionableRow.Path => MountPoint;
    string IActionableRow.DisplayName => string.IsNullOrEmpty(Device) ? "USB device" : Device;

    public static PortRowViewModel From(JsonRecord r)
    {
        var eventType = r.GetString("event_type") ?? r.GetString("type") ?? "usb event";
        var vid = r.GetString("vid") ?? r.GetNestedString("device", "vid") ?? "";
        var pid = r.GetString("pid") ?? r.GetNestedString("device", "pid") ?? "";
        var product = r.GetString("product") ?? r.GetNestedString("device", "product") ?? "";
        var manufacturer = r.GetString("manufacturer") ?? r.GetNestedString("device", "manufacturer") ?? "";

        string detail;
        if (r.Is("type", "usb_injection_alert"))
        {
            var suspected = r.GetBool("hid_injection_suspected") ?? false;
            detail = suspected
                ? $"HID injection suspected — mean interval {r.GetDouble("mean_interval_ms"):0.0}ms, stddev {r.GetDouble("stddev_interval_ms"):0.0}ms, n={r.GetLong("sample_count")}"
                : $"Typing rhythm looked human — mean interval {r.GetDouble("mean_interval_ms"):0.0}ms, n={r.GetLong("sample_count")}";
        }
        else if (r.Is("event_type", "USB_SESSION_END"))
        {
            detail = $"Session ended — reads {r.GetNestedLong("activity", "reads")}, writes {r.GetNestedLong("activity", "writes")}, " +
                     $"bytes written {r.GetNestedLong("activity", "bytes_written")}";
        }
        else
        {
            detail = r.RawLine.Length > 160 ? r.RawLine[..160] + "…" : r.RawLine;
        }

        return new PortRowViewModel
        {
            Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
            EventType = eventType,
            Device = string.IsNullOrEmpty(product) ? manufacturer : product,
            VidPid = string.IsNullOrEmpty(vid) ? "" : $"{vid}:{pid}",
            MountPoint = r.GetString("mount_point") ?? "",
            Detail = detail,
            SessionId = r.GetString("session_id") ?? r.GetString("instance_id") ?? "",
            Manufacturer = manufacturer,
            IsArrival = eventType is "USB_DEVICE_ARRIVED" or "USB_HID_KEYBOARD_ARRIVED",
            IsSessionEnd = eventType == "USB_SESSION_END",
            IsHistorical = r.IsSeedHistory,
            GenerationKey = $"{eventType}:{r.GetString("session_id") ?? r.GetString("instance_id") ?? r.SequenceId.ToString()}"
        };
    }
}
