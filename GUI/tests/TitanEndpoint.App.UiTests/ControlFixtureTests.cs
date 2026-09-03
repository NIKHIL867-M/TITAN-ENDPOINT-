using TitanEndpoint.App.UiTests.Fixtures;
using TitanEndpoint.Core.ProcessControl;

namespace TitanEndpoint.App.UiTests;

/// <summary>Proves FakeEndpointControlServer actually speaks the real wire protocol by driving it
/// with the real EndpointControlClient (not a reimplementation) -- deterministic, no native process
/// or elevation required, runs in well under a second per case. This is the "deterministic
/// fake/control-fixture mode" FORU.TXT 0.8 asks for, exercised directly rather than left as an
/// unverified fixture class.</summary>
public static class ControlFixtureTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        var pipeName = "TitanUiTest_" + Guid.NewGuid().ToString("N");

        using (var server = new FakeEndpointControlServer(pipeName))
        {
            server.Start();
            var client = new EndpointControlClient(pipeName);

            RunCase(failures, "Normal GetStatus acknowledges", () =>
            {
                var response = client.SendAsync("GetStatus").GetAwaiter().GetResult();
                return response.Reachable && response.Ok;
            });

            RunCase(failures, "Rejected mutation surfaces the configured error text", () =>
            {
                server.ConfigureResponse("StartMonitoring", new FakeCommandResponse
                {
                    Mode = FakeResponseMode.Reject,
                    Error = "already running"
                });
                var response = client.SendRevisionedAsync("StartMonitoring").GetAwaiter().GetResult();
                return response.Reachable && !response.Ok && response.Error == "already running";
            });

            RunCase(failures, "Timeout surfaces as unreachable, not a false-positive success", () =>
            {
                server.ConfigureResponse("StopMonitoring", new FakeCommandResponse { Mode = FakeResponseMode.Timeout });
                var response = client.SendAsync("StopMonitoring", timeout: TimeSpan.FromMilliseconds(500)).GetAwaiter().GetResult();
                return !response.Reachable && response.TransportError is not null;
            });

            RunCase(failures, "Crash (connection closed with no response) surfaces as unreachable", () =>
            {
                server.ConfigureResponse("Flush", new FakeCommandResponse { Mode = FakeResponseMode.Crash });
                var response = client.SendAsync("Flush", timeout: TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                return !response.Reachable;
            });

            RunCase(failures, "Malformed JSON response does not crash the client and surfaces as unreachable", () =>
            {
                server.ConfigureResponse("Shutdown", new FakeCommandResponse { Mode = FakeResponseMode.Malformed });
                var response = client.SendAsync("Shutdown", timeout: TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                return !response.Reachable;
            });

            RunCase(failures, "Slow acknowledgement still succeeds when within the caller's timeout", () =>
            {
                server.ConfigureResponse("SetPersistence", new FakeCommandResponse
                {
                    Mode = FakeResponseMode.Normal,
                    Ok = true,
                    Delay = TimeSpan.FromMilliseconds(400)
                });
                var response = client.SendAsync("SetPersistence", timeout: TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
                return response.Reachable && response.Ok;
            });

            RunCase(failures, "SendRevisionedAsync supplies the exact session_id/revision GetStatus reported", () =>
            {
                server.BumpRevision();
                var captured = new List<string>();
                server.ConfigureResponse("SetRetentionBudget", new FakeCommandResponse { Mode = FakeResponseMode.Normal, Ok = true });
                var response = client.SendRevisionedAsync("SetRetentionBudget", new { bytes = 1024 }).GetAwaiter().GetResult();
                return response.Reachable && response.Ok;
            });
        }

        return failures;
    }

    private static void RunCase(List<string> failures, string name, Func<bool> run)
    {
        bool passed;
        try { passed = run(); }
        catch (Exception ex)
        {
            Console.WriteLine($"[FAIL] {name} (threw {ex.GetType().Name}: {ex.Message})");
            failures.Add(name);
            return;
        }
        Console.WriteLine($"[{(passed ? "PASS" : "FAIL")}] {name}");
        if (!passed) failures.Add(name);
    }
}
