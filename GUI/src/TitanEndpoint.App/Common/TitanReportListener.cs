using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace TitanEndpoint.App.Common;

/// <summary>One received push from whatever is on the other end of the exchange (e.g. an OpenCTI-side
/// script reporting back after it finished processing a bundle this app sent it).</summary>
public sealed class ReceivedReport
{
    public DateTimeOffset ReceivedAtUtc { get; init; }
    public string RemoteAddress { get; init; } = "";
    public string ContentType { get; init; } = "";
    public string Body { get; init; } = "";
}

/// <summary>
/// Santosh, 2026-08-27: "create a 2-way port in this application to send and receive information."
/// This is the receive half -- a small embedded HTTP listener (no extra dependencies: HttpListener
/// is built into .NET) so a remote script (e.g. on the OpenCTI laptop) can push a report back to
/// TITAN whenever it's actually ready, instead of TITAN having to block waiting for a synchronous
/// response to its own outgoing send.
///
/// Security note (this is a security monitoring tool -- an unauthenticated listening port on it
/// would be a real, slightly ironic hole): every request must present the same shared token TITAN's
/// own outgoing sends use, in an "X-Titan-Token" header, or it's rejected with 401. Anyone without
/// the token gets nothing.
///
/// Binding: tries all network interfaces first (works when this process is elevated, which it
/// already is whenever "Start All" is used, or once a URL ACL is registered). If that's refused
/// (HttpListenerException -- not elevated, no ACL), falls back to loopback-only, which Windows
/// always allows with no elevation or ACL requirement, so this never simply fails to start; it may
/// just be reachable only from this same machine until run elevated.
/// </summary>
public sealed class TitanReportListener : IDisposable
{
    public int Port { get; }
    public string SharedToken { get; set; } = "";
    public bool IsListeningOnAllInterfaces { get; private set; }
    public bool IsRunning { get; private set; }

    public event Action<ReceivedReport>? ReportReceived;
    public event Action<string>? ListenerError;

    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    public TitanReportListener(int port) { Port = port; }

    public void Start()
    {
        Stop();
        _cts = new CancellationTokenSource();
        try
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://+:{Port}/titan/");
            _listener.Start();
            IsListeningOnAllInterfaces = true;
        }
        catch (HttpListenerException)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{Port}/titan/");
            _listener.Start();
            IsListeningOnAllInterfaces = false;
        }
        IsRunning = true;
        _ = AcceptLoopAsync(_cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        var listener = _listener;
        if (listener is null) return;
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                break; // listener stopped/disposed -- normal on shutdown
            }
            _ = Task.Run(() => Handle(ctx), ct);
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            if (ctx.Request.HttpMethod != "POST")
            {
                ctx.Response.StatusCode = 405;
                ctx.Response.Close();
                return;
            }

            var presented = ctx.Request.Headers["X-Titan-Token"] ?? "";
            if (!string.IsNullOrEmpty(SharedToken) && !ConstantTimeEquals(presented, SharedToken))
            {
                ctx.Response.StatusCode = 401;
                var denyBytes = Encoding.UTF8.GetBytes("{\"ok\":false,\"error\":\"bad or missing X-Titan-Token\"}");
                ctx.Response.ContentType = "application/json";
                ctx.Response.OutputStream.Write(denyBytes, 0, denyBytes.Length);
                ctx.Response.Close();
                return;
            }

            string body;
            using (var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
                body = reader.ReadToEnd();

            var report = new ReceivedReport
            {
                ReceivedAtUtc = DateTimeOffset.UtcNow,
                RemoteAddress = ctx.Request.RemoteEndPoint?.ToString() ?? "unknown",
                ContentType = ctx.Request.ContentType ?? "",
                Body = body
            };

            var okBytes = Encoding.UTF8.GetBytes("{\"ok\":true}");
            ctx.Response.ContentType = "application/json";
            ctx.Response.StatusCode = 200;
            ctx.Response.OutputStream.Write(okBytes, 0, okBytes.Length);
            ctx.Response.Close();

            ReportReceived?.Invoke(report);
        }
        catch (Exception ex)
        {
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { /* best effort */ }
            ListenerError?.Invoke(ex.Message);
        }
    }

    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    /// <summary>Best real LAN-reachable IPv4 address for this machine, so the UI can tell the user
    /// exactly what to point the other side at -- 127.0.0.1 would be useless for that since it only
    /// ever means "this same machine" to whoever we give it to.</summary>
    public static string GetBestLocalIPv4()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        return addr.Address.ToString();
                }
            }
        }
        catch (NetworkInformationException) { /* fall through to loopback */ }
        return "127.0.0.1";
    }

    public void Stop()
    {
        IsRunning = false;
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { /* best effort */ }
        try { _listener?.Close(); } catch { /* best effort */ }
        _listener = null;
    }

    public void Dispose() => Stop();
}
