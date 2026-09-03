namespace TitanEndpoint.App.ViewModels;

public sealed class UsbDeviceCardViewModel
{
    public required string SessionId { get; init; }
    public required string Device { get; init; }
    public string Manufacturer { get; init; } = "";
    public string VidPid { get; init; } = "";
    public string MountPoint { get; init; } = "";
    public string ConnectedAt { get; init; } = "";
    public string Kind { get; init; } = "USB device";
}
