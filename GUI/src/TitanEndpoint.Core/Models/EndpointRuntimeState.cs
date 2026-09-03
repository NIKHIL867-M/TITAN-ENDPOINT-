using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Diagnostics;
using TitanEndpoint.Core.Logs;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.Core.Models;

/// <summary>
/// Live state for one collector: whether the OS process is actually running,
/// plus its log tailer. This is the one object every page's ViewModel binds
/// against for a given endpoint.
/// </summary>
public sealed class EndpointRuntimeState
{
    public EndpointDefinition Definition { get; }
    public EndpointProcessController Controller { get; }
    public LogTailer Tailer { get; }
    public EndpointDiagnostics Diagnostics { get; }
    public RunningProcessInfo? Running { get; private set; }
    public DateTimeOffset? LastProcessCheckUtc { get; private set; }

    /// <summary>Single shared client for this endpoint's authenticated named-pipe control channel
    /// -- null when no channel is configured. Shared (not one instance per consumer) because each
    /// SendAsync call already opens and closes its own pipe connection, so there is no benefit to
    /// duplicating the object, only redundant construction; both EndpointHeaderViewModel and
    /// LogTailer's GetRecentEvents fallback use this exact same instance.</summary>
    public EndpointControlClient? ControlClient { get; }

    public EndpointRuntimeState(EndpointDefinition definition, int tailerCapacity = 5000)
    {
        Definition = definition;
        Controller = new EndpointProcessController(definition);
        Tailer = new LogTailer(definition, tailerCapacity);
        Diagnostics = new EndpointDiagnostics(definition.DisplayName);
        Controller.Diagnostics = Diagnostics;

        if (definition.ManifestControlChannelImplemented && !string.IsNullOrEmpty(definition.ManifestControlChannelName))
        {
            ControlClient = new EndpointControlClient(definition.ManifestControlChannelName);
            Tailer.ControlClient = ControlClient;
        }
    }

    public bool IsRunning => Running is not null;

    public void BeginTailing() => Tailer.Start();

    public void RefreshProcessState()
    {
        Running = Controller.DetectRunning();
        LastProcessCheckUtc = DateTimeOffset.UtcNow;
    }

    public void Dispose() => Tailer.Stop();
}
