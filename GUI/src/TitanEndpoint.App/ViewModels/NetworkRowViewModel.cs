using System.Text.Json;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class NetworkRowViewModel
{
    public string Time { get; init; } = "";
    public string Process { get; init; } = "";
    public string LocalAddress { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public string LocalIp { get; init; } = "";
    public string RemoteIp { get; init; } = "";
    public long LocalPort { get; init; }
    public long RemotePort { get; init; }
    public string Protocol { get; init; } = "";
    public string Direction { get; init; } = "";
    public string State { get; init; } = "";
    public long BytesSent { get; init; }
    public long BytesRecv { get; init; }
    public long Length { get; init; }
    public string Adapter { get; init; } = "";
    public ulong CaptureEpochUs { get; init; }
    public bool RawCaptureMapped { get; init; }
    public string RawCaptureSegment { get; init; } = "";
    public long RawRecordOffset { get; init; }
    public long RawDataOffset { get; init; }

    // Additional fields carried through only for the protocol detail tree (spec section 8,
    // middle pane) — not shown as DataGrid columns, so keep them off the default view.
    public long Pid { get; init; }
    public string EtherType { get; init; } = "";
    public long TransportProtocolNumber { get; init; }
    public string PacketSrcIp { get; init; } = "";
    public string PacketDstIp { get; init; } = "";
    public bool Ipv6 { get; init; }
    public bool IsBroadcast { get; init; }
    public bool IsLoopback { get; init; }
    public bool Fragmented { get; init; }
    public long FragmentOffset { get; init; }
    public bool MoreFragments { get; init; }
    public string VlanIds { get; init; } = "";
    public long PacketCount { get; init; }
    public long FlowDurationMs { get; init; }
    public long PayloadLength { get; init; }
    public string DnsQuery { get; init; } = "";
    public string DnsQueryType { get; init; } = "";
    public string DnsAnswers { get; init; } = "";
    public string TlsSni { get; init; } = "";
    public string HttpMethod { get; init; } = "";
    public string HttpTarget { get; init; } = "";
    public string HttpHost { get; init; } = "";
    public long? HttpStatusCode { get; init; }
    public string HttpReason { get; init; } = "";
    public string ExpectedProtocol { get; init; } = "";
    public bool? ProtocolMismatch { get; init; }

    /// <summary>Pretty-printed raw JSON for this record — advanced/raw tab, same convention as
    /// Custom Rule's "raw IR as advanced tab" (spec section 13).</summary>
    public string RawJson { get; init; } = "";

    public static NetworkRowViewModel From(JsonRecord r)
    {
        var pid = r.GetLong("pid") ?? 0;
        var pname = r.GetString("process_name");

        var vlanIds = "";
        if (r.Root.TryGetProperty("vlan_ids", out var vlanEl) && vlanEl.ValueKind == JsonValueKind.Array)
        {
            vlanIds = string.Join(", ", vlanEl.EnumerateArray()
                .Select(e => e.ValueKind == JsonValueKind.Number ? e.GetRawText() : e.ToString()));
        }

        var dnsAnswers = "";
        if (r.Root.TryGetProperty("dns_answers", out var ansEl) && ansEl.ValueKind == JsonValueKind.Array)
        {
            dnsAnswers = string.Join(", ", ansEl.EnumerateArray()
                .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString()));
        }

        string rawJson;
        try
        {
            rawJson = JsonSerializer.Serialize(r.Root, new JsonSerializerOptions { WriteIndented = true });
        }
        catch { rawJson = r.RawLine; }

        var localIp = r.GetString("local_ip") ?? "";
        var remoteIp = r.GetString("remote_ip") ?? "";
        var localPort = r.GetLong("local_port") ?? 0;
        var remotePort = r.GetLong("remote_port") ?? 0;
        return new NetworkRowViewModel
        {
            Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
            Process = string.IsNullOrEmpty(pname) ? (pid > 0 ? $"pid {pid}" : "Unattributed") : $"{pname} ({pid})",
            LocalAddress = $"{localIp}:{localPort}",
            RemoteAddress = $"{remoteIp}:{remotePort}",
            LocalIp = localIp,
            RemoteIp = remoteIp,
            LocalPort = localPort,
            RemotePort = remotePort,
            Protocol = r.GetString("protocol") ?? "",
            Direction = r.GetString("direction") ?? "",
            State = r.GetString("state") ?? "",
            BytesSent = r.GetLong("bytes_sent") ?? 0,
            BytesRecv = r.GetLong("bytes_recv") ?? 0,
            Length = r.GetLong("captured_length") ?? r.GetLong("wire_length") ?? 0,
            Adapter = r.GetString("adapter") ?? "",
            CaptureEpochUs = (ulong)Math.Max(0, r.GetLong("capture_epoch_us") ?? 0),
            RawCaptureMapped = r.GetBool("raw_capture_mapped") ?? false,
            RawCaptureSegment = r.GetString("raw_capture_segment") ?? "",
            RawRecordOffset = r.GetLong("raw_record_offset") ?? 0,
            RawDataOffset = r.GetLong("raw_data_offset") ?? 0,

            Pid = pid,
            EtherType = r.GetString("ether_type") ?? "",
            TransportProtocolNumber = r.GetLong("transport_protocol") ?? 0,
            PacketSrcIp = r.GetString("packet_src_ip") ?? "",
            PacketDstIp = r.GetString("packet_dst_ip") ?? "",
            Ipv6 = r.GetBool("ipv6") ?? false,
            IsBroadcast = r.GetBool("is_broadcast") ?? false,
            IsLoopback = r.GetBool("is_loopback") ?? false,
            Fragmented = r.GetBool("fragmented") ?? false,
            FragmentOffset = r.GetLong("fragment_offset") ?? 0,
            MoreFragments = r.GetBool("more_fragments") ?? false,
            VlanIds = vlanIds,
            PacketCount = r.GetLong("packet_count") ?? 0,
            FlowDurationMs = r.GetLong("flow_duration_ms") ?? 0,
            PayloadLength = r.GetLong("payload_length") ?? 0,
            DnsQuery = r.GetString("dns_query") ?? "",
            DnsQueryType = r.GetString("dns_query_type") ?? "",
            DnsAnswers = dnsAnswers,
            TlsSni = r.GetString("tls_sni") ?? "",
            HttpMethod = r.GetString("http_method") ?? "",
            HttpTarget = r.GetString("http_target") ?? "",
            HttpHost = r.GetString("http_host") ?? "",
            HttpStatusCode = r.GetLong("http_status_code"),
            HttpReason = r.GetString("http_reason") ?? "",
            ExpectedProtocol = r.GetString("expected_protocol") ?? "",
            ProtocolMismatch = r.GetBool("protocol_mismatch"),
            RawJson = rawJson
        };
    }
}
