using TitanEndpoint.Core.Config;

namespace TitanEndpoint.Core.Models;

/// <summary>
/// Owns one EndpointRuntimeState per configured endpoint (all 6 native
/// collectors plus Custom Rule) for the lifetime of the application. Single
/// shared instance the whole GUI reads from.
/// </summary>
public sealed class TitanFleet
{
    public TitanSettings Settings { get; }
    public IReadOnlyDictionary<EndpointId, EndpointRuntimeState> Endpoints { get; }

    public TitanFleet(TitanSettings settings)
    {
        Settings = settings;
        var map = new Dictionary<EndpointId, EndpointRuntimeState>();
        foreach (var def in settings.Endpoints)
            map[def.Id] = new EndpointRuntimeState(def);
        Endpoints = map;
    }

    public EndpointRuntimeState Get(EndpointId id) => Endpoints[id];

    public void StartAllTailers()
    {
        foreach (var e in Endpoints.Values)
            e.BeginTailing();
    }

    public void RefreshAllProcessStates()
    {
        foreach (var e in Endpoints.Values)
            e.RefreshProcessState();
    }

    public void Shutdown()
    {
        foreach (var e in Endpoints.Values)
            e.Dispose();
    }
}
