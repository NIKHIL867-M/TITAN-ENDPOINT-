using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace TitanEndpoint.App.UiTests.Fixtures;

public enum FakeResponseMode { Normal, Reject, Timeout, Malformed, Crash }

public sealed class FakeCommandResponse
{
    public FakeResponseMode Mode { get; init; } = FakeResponseMode.Normal;
    public bool Ok { get; init; } = true;
    public string? Error { get; init; }
    public Dictionary<string, object?> ExtraFields { get; init; } = new();
    public TimeSpan Delay { get; init; } = TimeSpan.Zero;
}

/// <summary>FORU.TXT 0.8: "Add a deterministic fake/control-fixture mode for rejection, timeout,
/// stale revision, crash, malformed data, slow acknowledgement, partial Start All, and missing
/// dependency states." A named-pipe SERVER implementing the exact same wire protocol
/// EndpointControlClient (GUI\src\TitanEndpoint.Core\ProcessControl\EndpointControlClient.cs)
/// speaks as a client -- {"proto_version":1,"request_id":..,"command":..,...} in, one JSON object
/// with at least "ok" out -- so ViewModel-level tests can exercise every rejection/timeout/crash
/// path deterministically, in milliseconds, without needing a real native process or elevation.
/// Not yet wired into EndpointHeaderViewModel-level tests (which would require constructing a
/// ViewModel against this fake pipe name instead of a real endpoint's) -- that integration is the
/// next step once this fixture itself is proven correct, verified below in ControlFixtureTests.
/// </summary>
public sealed class FakeEndpointControlServer : IDisposable
{
    private readonly string _pipeName;
    private readonly Dictionary<string, FakeCommandResponse> _responses = new(StringComparer.Ordinal);
    private FakeCommandResponse _default = new();
    private readonly string _sessionId = Guid.NewGuid().ToString("N");
    private long _revision = 1;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public FakeEndpointControlServer(string pipeName) => _pipeName = pipeName;

    public void ConfigureResponse(string command, FakeCommandResponse response) => _responses[command] = response;
    public void ConfigureDefault(FakeCommandResponse response) => _default = response;
    public void BumpRevision() => Interlocked.Increment(ref _revision);

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(() => ListenLoopAsync(_cts.Token));
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var server = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, 4,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            try
            {
                await server.WaitForConnectionAsync(ct);
            }
            catch (OperationCanceledException)
            {
                server.Dispose();
                break;
            }
            catch (IOException)
            {
                server.Dispose();
                continue;
            }
            _ = HandleConnectionAsync(server, ct);
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        using var owned = server;
        try
        {
            var buffer = new byte[8192];
            using var ms = new MemoryStream();
            string? command = null;
            while (true)
            {
                var read = await owned.ReadAsync(buffer, ct);
                if (read == 0) return;
                ms.Write(buffer, 0, read);
                try
                {
                    using var doc = JsonDocument.Parse(ms.GetBuffer().AsMemory(0, (int)ms.Length));
                    command = doc.RootElement.TryGetProperty("command", out var c) ? c.GetString() : null;
                    break;
                }
                catch (JsonException)
                {
                    // A complete request can arrive across multiple pipe reads.
                }
            }
            if (command is null) return;

            var config = _responses.TryGetValue(command, out var cfg) ? cfg : _default;
            if (config.Delay > TimeSpan.Zero) await Task.Delay(config.Delay, ct);

            switch (config.Mode)
            {
                case FakeResponseMode.Timeout:
                    await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                    return;
                case FakeResponseMode.Crash:
                    return; // connection closes with nothing written -- client sees a transport error
                case FakeResponseMode.Malformed:
                    var garbage = Encoding.UTF8.GetBytes("{not valid json");
                    await owned.WriteAsync(garbage, ct);
                    await owned.FlushAsync(ct);
                    return;
            }

            var fields = new Dictionary<string, object?>(config.ExtraFields, StringComparer.Ordinal)
            {
                ["ok"] = config.Mode == FakeResponseMode.Reject ? false : config.Ok
            };
            if (config.Error is not null) fields["error"] = config.Error;
            if (command == "GetStatus" && !fields.ContainsKey("session_id"))
            {
                fields["session_id"] = _sessionId;
                fields["revision"] = Interlocked.Read(ref _revision);
            }

            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fields));
            await owned.WriteAsync(bytes, ct);
            await owned.FlushAsync(ct);
        }
        catch (OperationCanceledException) { }
        catch (IOException) { } // client disconnected mid-response -- not a fixture failure
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _listenTask?.Wait(TimeSpan.FromSeconds(2)); } catch { /* best effort */ }
        _cts?.Dispose();
    }
}
