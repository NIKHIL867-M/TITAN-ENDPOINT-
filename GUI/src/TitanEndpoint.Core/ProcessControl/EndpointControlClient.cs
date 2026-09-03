using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace TitanEndpoint.Core.ProcessControl;

public sealed class ControlResponse
{
    public bool Ok { get; init; }
    public string? Error { get; init; }
    public JsonElement Root { get; init; }
    public string? TransportError { get; init; }

    public bool Reachable => TransportError is null;
}

/// <summary>
/// Endpoint-agnostic client for the authenticated named-pipe control protocol implemented by
/// every native TITAN component. Mutating calls should use SendRevisionedAsync so the request is
/// bound to the exact native process session and state revision observed immediately beforehand.
/// </summary>
public sealed class EndpointControlClient
{
    private const int MaxResponseBytes = 2 * 1024 * 1024;
    private readonly string _pipeName;
    private static int _requestCounter;

    public EndpointControlClient(string pipeName)
    {
        const string prefix = @"\\.\pipe\";
        _pipeName = pipeName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? pipeName[prefix.Length..]
            : pipeName;
    }

    public async Task<ControlResponse> SendAsync(string command, object? extraParams = null,
        TimeSpan? timeout = null, CancellationToken ct = default)
    {
        timeout ??= TimeSpan.FromSeconds(5);
        try
        {
            using var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous);
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeout.Value);
            await client.ConnectAsync(connectCts.Token);

            var requestId = $"gui-{Environment.ProcessId}-{Interlocked.Increment(ref _requestCounter)}";
            var payload = new Dictionary<string, object?>
            {
                ["proto_version"] = 1,
                ["request_id"] = requestId,
                ["command"] = command
            };
            foreach (var (key, value) in ToFields(extraParams)) payload[key] = value;

            var requestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
            await client.WriteAsync(requestBytes, ct);
            await client.FlushAsync(ct);

            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeout.Value);
            using var responseBytes = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                var read = await client.ReadAsync(buffer, readCts.Token);
                if (read == 0) break;
                responseBytes.Write(buffer, 0, read);
                if (responseBytes.Length > MaxResponseBytes)
                    throw new IOException($"Control response exceeded the {MaxResponseBytes:N0}-byte safety limit.");

                try
                {
                    using var complete = JsonDocument.Parse(
                        responseBytes.GetBuffer().AsMemory(0, (int)responseBytes.Length));
                    break;
                }
                catch (JsonException)
                {
                    // A valid response can span multiple named-pipe reads.
                }
            }

            var responseJson = Encoding.UTF8.GetString(responseBytes.ToArray());
            using var doc = JsonDocument.Parse(responseJson);
            var root = doc.RootElement.Clone();
            var ok = root.TryGetProperty("ok", out var okElement) && okElement.ValueKind == JsonValueKind.True;
            var error = root.TryGetProperty("error", out var errorElement) &&
                        errorElement.ValueKind == JsonValueKind.String
                ? errorElement.GetString()
                : null;
            return new ControlResponse { Ok = ok, Error = error, Root = root };
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or
                                   JsonException or UnauthorizedAccessException)
        {
            return new ControlResponse { Ok = false, TransportError = ex.Message, Root = default };
        }
    }

    public async Task<ControlResponse> SendRevisionedAsync(string command, object? extraParams = null,
        TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var status = await SendAsync("GetStatus", timeout: timeout, ct: ct);
        if (!status.Reachable || !status.Ok) return status;

        if (!status.Root.TryGetProperty("session_id", out var sessionElement) ||
            sessionElement.ValueKind != JsonValueKind.String ||
            !status.Root.TryGetProperty("revision", out var revisionElement) ||
            !revisionElement.TryGetInt64(out var revision))
        {
            return new ControlResponse
            {
                Ok = false,
                Error = "Control status omitted session_id or revision; refusing an unbound mutation.",
                Root = status.Root
            };
        }

        var fields = ToFields(extraParams);
        fields["expected_session_id"] = sessionElement.GetString();
        fields["expected_revision"] = revision;
        return await SendAsync(command, fields, timeout, ct);
    }

    public async Task<bool> IsReachableAsync(CancellationToken ct = default)
    {
        var response = await SendAsync("GetStatus", timeout: TimeSpan.FromMilliseconds(800), ct: ct);
        return response.Reachable && response.Ok;
    }

    private static Dictionary<string, object?> ToFields(object? value)
    {
        if (value is null) return new Dictionary<string, object?>();
        if (value is IReadOnlyDictionary<string, object?> readOnly)
            return new Dictionary<string, object?>(readOnly, StringComparer.Ordinal);
        if (value is IDictionary<string, object?> dictionary)
            return new Dictionary<string, object?>(dictionary, StringComparer.Ordinal);

        return value.GetType().GetProperties()
            .ToDictionary(property => property.Name, property => property.GetValue(value),
                StringComparer.Ordinal);
    }
}
