namespace TitanEndpoint.Core.ProcessControl;

public sealed class RunningProcessInfo
{
    public required int Pid { get; init; }
    public required DateTime StartTimeUtc { get; init; }
    public string? ExecutablePath { get; init; }

    /// <summary>True once this process's executable path has been read and confirmed to match
    /// the configured executable (see EndpointProcessController.DetectRunning) — a same-named
    /// process whose path does NOT match is never returned as a RunningProcessInfo at all, so by
    /// the time one exists, PathVerified=false only means the path could not be read (should be
    /// rare — see ProcessImagePath), never "read but different."</summary>
    public bool PathVerified { get; init; }
}
