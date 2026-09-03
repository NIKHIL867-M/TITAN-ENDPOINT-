using System.Text.Json;
using TitanEndpoint.Core.Models;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.Core.Config;

public sealed record EndpointBudgetResult(EndpointId Endpoint, long BudgetBytes, string State, string? Detail);

/// <summary>
/// Converts the one product-level disk budget into explicit per-native-endpoint limits and
/// applies them through authenticated, session/revision-bound IPC. Results are persisted
/// atomically so the GUI and support reports can distinguish Applied from Pending/Rejected.
/// Resource-pressure logic may shrink these limits but native loggers are not allowed to grow
/// above them again.
/// </summary>
public sealed class DiskBudgetCoordinator
{
    private static readonly IReadOnlyDictionary<EndpointId, int> Weights =
        new Dictionary<EndpointId, int>
        {
            [EndpointId.Process] = 20,
            [EndpointId.Network] = 35, // JSON plus bounded raw PCAP is the largest producer.
            [EndpointId.Application] = 10,
            [EndpointId.File] = 15,
            [EndpointId.Port] = 5,
            [EndpointId.Correlator] = 15
        };

    private readonly Dictionary<EndpointId, (string Session, long Budget)> _applied = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<IReadOnlyList<EndpointBudgetResult>> ApplyAsync(TitanFleet fleet,
        CancellationToken cancellationToken = default)
    {
        if (!await _gate.WaitAsync(0, cancellationToken)) return Array.Empty<EndpointBudgetResult>();
        try
        {
            var freeBytes = GetAvailableBytes(fleet.Settings.TitanRootDirectory);
            var reserve = Math.Max(0, fleet.Settings.MinimumFreeSpaceReserveBytes);
            var pressureCeiling = freeBytes == long.MaxValue ? fleet.Settings.GlobalDiskBudgetBytes
                : Math.Max(fleet.Settings.GlobalDiskBudgetBytes / 10, freeBytes - reserve);
            var effectiveBudget = Math.Max(6L * 1024 * 1024,
                Math.Min(fleet.Settings.GlobalDiskBudgetBytes, pressureCeiling));
            var allocations = Allocate(effectiveBudget);
            var results = new List<EndpointBudgetResult>();
            foreach (var (endpointId, budgetBytes) in allocations)
            {
                var state = fleet.Get(endpointId);
                state.RefreshProcessState();
                var definition = state.Definition;
                if (!state.IsRunning)
                {
                    results.Add(new EndpointBudgetResult(endpointId, budgetBytes, "Pending",
                        "Endpoint is stopped; the budget will be applied after it starts."));
                    continue;
                }
                if (!definition.ManifestControlChannelImplemented ||
                    string.IsNullOrWhiteSpace(definition.ManifestControlChannelName))
                {
                    results.Add(new EndpointBudgetResult(endpointId, budgetBytes, "Rejected",
                        "Authenticated control channel is unavailable."));
                    continue;
                }

                var client = new EndpointControlClient(definition.ManifestControlChannelName);
                var status = await client.SendAsync("GetStatus", timeout: TimeSpan.FromSeconds(2),
                    ct: cancellationToken);
                var session = status.Ok && status.Root.TryGetProperty("session_id", out var sessionElement) &&
                              sessionElement.ValueKind == JsonValueKind.String
                    ? sessionElement.GetString()
                    : null;
                if (session is not null && _applied.TryGetValue(endpointId, out var previous) &&
                    previous.Session == session && previous.Budget == budgetBytes)
                {
                    results.Add(new EndpointBudgetResult(endpointId, budgetBytes, "Applied", "Already active for this native session."));
                    continue;
                }

                var response = await client.SendRevisionedAsync("SetRetentionBudget",
                    new { budget_bytes = budgetBytes }, TimeSpan.FromSeconds(4), cancellationToken);
                if (response.Ok && response.Root.TryGetProperty("session_id", out var acceptedSession) &&
                    acceptedSession.ValueKind == JsonValueKind.String)
                {
                    var accepted = acceptedSession.GetString() ?? session ?? "unknown";
                    _applied[endpointId] = (accepted, budgetBytes);
                    results.Add(new EndpointBudgetResult(endpointId, budgetBytes, "Applied",
                        response.Root.TryGetProperty("retention_pack_limit", out var packs)
                            ? $"Native pack limit {packs}."
                            : response.Root.TryGetProperty("retention_archive_limit", out var archives)
                                ? $"Native archive limit {archives}."
                                : "Native endpoint acknowledged the budget."));
                }
                else
                {
                    results.Add(new EndpointBudgetResult(endpointId, budgetBytes, "Rejected",
                        response.Reachable ? response.Error : response.TransportError));
                }
            }

            WriteReport(fleet.Settings, results, effectiveBudget, freeBytes);
            return results;
        }
        finally
        {
            _gate.Release();
        }
    }

    public static IReadOnlyDictionary<EndpointId, long> Allocate(long globalBytes)
    {
        if (globalBytes <= 0) throw new ArgumentOutOfRangeException(nameof(globalBytes));
        var result = new Dictionary<EndpointId, long>();
        long allocated = 0;
        foreach (var item in Weights.Take(Weights.Count - 1))
        {
            var bytes = checked(globalBytes * item.Value / 100);
            result[item.Key] = bytes;
            allocated += bytes;
        }
        var last = Weights.Last();
        result[last.Key] = globalBytes - allocated;
        return result;
    }

    private static long GetAvailableBytes(string root)
    {
        try
        {
            var full = Path.GetFullPath(root);
            var driveRoot = Path.GetPathRoot(full);
            return string.IsNullOrWhiteSpace(driveRoot) ? long.MaxValue : new DriveInfo(driveRoot).AvailableFreeSpace;
        }
        catch (Exception) { return long.MaxValue; }
    }

    private static void WriteReport(TitanSettings settings, IReadOnlyList<EndpointBudgetResult> results,
        long effectiveBudget, long freeBytes)
    {
        var runtimeDirectory = Path.Combine(settings.TitanRootDirectory, ".titan-runtime");
        Directory.CreateDirectory(runtimeDirectory);
        var path = Path.Combine(runtimeDirectory, "retention_budgets.json");
        var temporary = path + ".tmp";
        var json = JsonSerializer.Serialize(new
        {
            schema_version = 1,
            generated_at = DateTimeOffset.UtcNow,
            global_budget_bytes = settings.GlobalDiskBudgetBytes,
            effective_native_budget_bytes = effectiveBudget,
            available_free_bytes = freeBytes == long.MaxValue ? (long?)null : freeBytes,
            minimum_free_space_reserve_bytes = settings.MinimumFreeSpaceReserveBytes,
            pressure_limited = effectiveBudget < settings.GlobalDiskBudgetBytes,
            evidence_policy = "CUSTOM RULE evidence uses its independent severity/age/file/byte retention policy; native allocations never delete that evidence store.",
            endpoints = results.Select(result => new
            {
                endpoint = result.Endpoint.ToString(),
                budget_bytes = result.BudgetBytes,
                state = result.State,
                detail = result.Detail
            })
        }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temporary, json, new System.Text.UTF8Encoding(false));
        File.Move(temporary, path, true);
    }
}
