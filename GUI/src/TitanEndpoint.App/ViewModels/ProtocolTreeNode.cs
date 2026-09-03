using System.Collections.ObjectModel;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// One row of the Network page's expandable protocol tree (spec section 8, middle pane):
/// frame/capture metadata, link layer, IPv4/IPv6, transport, application metadata, TITAN
/// process attribution. Built entirely from fields already present in the JSONL record —
/// see NetworkRowViewModel for what the native endpoint currently emits.
/// </summary>
public sealed class ProtocolTreeNode
{
    public string Label { get; init; } = "";
    public string Value { get; init; } = "";
    public string FieldKey { get; init; } = "";
    public ObservableCollection<ProtocolTreeNode> Children { get; } = new();

    public static ObservableCollection<ProtocolTreeNode> Build(NetworkRowViewModel row)
    {
        var root = new ObservableCollection<ProtocolTreeNode>();

        var frame = Section("Frame / Capture");
        frame.Children.Add(Leaf("Captured length", row.Length > 0 ? $"{row.Length} bytes" : "Unavailable", "frame"));
        frame.Children.Add(Leaf("Adapter", string.IsNullOrEmpty(row.Adapter) ? "Unavailable" : row.Adapter));
        frame.Children.Add(Leaf("Time", row.Time));
        root.Add(frame);

        var link = Section("Link Layer");
        link.Children.Add(Leaf("Ether type", string.IsNullOrEmpty(row.EtherType) ? "Unavailable" : row.EtherType, "ether_type"));
        if (!string.IsNullOrEmpty(row.VlanIds)) link.Children.Add(Leaf("VLAN ID(s)", row.VlanIds));
        root.Add(link);

        var net = Section(row.Ipv6 ? "Network Layer — IPv6" : "Network Layer — IPv4");
        net.Children.Add(Leaf("Source", string.IsNullOrEmpty(row.PacketSrcIp) ? "Unavailable" : row.PacketSrcIp, "ip_source"));
        net.Children.Add(Leaf("Destination", string.IsNullOrEmpty(row.PacketDstIp) ? "Unavailable" : row.PacketDstIp, "ip_destination"));
        if (row.IsBroadcast) net.Children.Add(Leaf("Broadcast", "Yes"));
        if (row.IsLoopback) net.Children.Add(Leaf("Loopback", "Yes"));
        if (row.Fragmented)
        {
            net.Children.Add(Leaf("Fragmented", "Yes"));
            net.Children.Add(Leaf("Fragment offset", row.FragmentOffset.ToString()));
            net.Children.Add(Leaf("More fragments", row.MoreFragments ? "Yes" : "No"));
        }
        root.Add(net);

        var transport = Section("Transport");
        transport.Children.Add(Leaf("Protocol", row.TransportProtocolNumber > 0
            ? $"{row.Protocol} ({row.TransportProtocolNumber})" : row.Protocol, "ip_protocol"));
        if (!string.IsNullOrEmpty(row.ExpectedProtocol))
        {
            transport.Children.Add(Leaf("Expected protocol (by port)", row.ExpectedProtocol));
            if (row.ProtocolMismatch == true)
                transport.Children.Add(Leaf("Protocol mismatch", $"Yes — traffic on this port did not match {row.ExpectedProtocol}"));
        }
        transport.Children.Add(Leaf("Local", row.LocalAddress, "local_port"));
        transport.Children.Add(Leaf("Remote", row.RemoteAddress, "remote_port"));
        transport.Children.Add(Leaf("Direction", row.Direction));
        transport.Children.Add(Leaf("State", string.IsNullOrEmpty(row.State) ? "Unavailable" : row.State));
        transport.Children.Add(Leaf("Bytes sent / received", $"{row.BytesSent:N0} / {row.BytesRecv:N0}"));
        if (row.PacketCount > 0) transport.Children.Add(Leaf("Packets in flow", row.PacketCount.ToString("N0")));
        if (row.FlowDurationMs > 0) transport.Children.Add(Leaf("Flow duration", $"{row.FlowDurationMs:N0} ms"));
        root.Add(transport);

        var hasApp = !string.IsNullOrEmpty(row.DnsQuery) || !string.IsNullOrEmpty(row.TlsSni) ||
                     !string.IsNullOrEmpty(row.HttpHost) || !string.IsNullOrEmpty(row.HttpMethod);
        if (hasApp)
        {
            var app = Section("Application Layer");
            if (!string.IsNullOrEmpty(row.DnsQuery))
            {
                app.Children.Add(Leaf("DNS query", row.DnsQuery));
                if (!string.IsNullOrEmpty(row.DnsQueryType)) app.Children.Add(Leaf("DNS query type", row.DnsQueryType));
                if (!string.IsNullOrEmpty(row.DnsAnswers)) app.Children.Add(Leaf("DNS answers", row.DnsAnswers));
            }
            if (!string.IsNullOrEmpty(row.TlsSni)) app.Children.Add(Leaf("TLS SNI", row.TlsSni));
            if (!string.IsNullOrEmpty(row.HttpMethod) || !string.IsNullOrEmpty(row.HttpHost))
            {
                app.Children.Add(Leaf("HTTP host", string.IsNullOrEmpty(row.HttpHost) ? "Unavailable" : row.HttpHost));
                app.Children.Add(Leaf("HTTP method / target", $"{row.HttpMethod} {row.HttpTarget}".Trim()));
            }
            if (row.HttpStatusCode is not null)
                app.Children.Add(Leaf("HTTP status", $"{row.HttpStatusCode} {row.HttpReason}".Trim()));
            root.Add(app);
        }
        else
        {
            var app = Section("Application Layer");
            app.Children.Add(Leaf("", "Encrypted or unsupported — no application-layer metadata decoded for this record."));
            root.Add(app);
        }

        var attribution = Section("TITAN Process Attribution");
        attribution.Children.Add(Leaf("Process", row.Pid > 0 ? row.Process : "Unattributed"));
        attribution.Children.Add(row.Pid > 0
            ? Leaf("PID", row.Pid.ToString())
            : Leaf("", "No process could be attributed to this packet within the periodic socket-table snapshot window."));
        root.Add(attribution);

        return root;
    }

    private static ProtocolTreeNode Section(string label) => new() { Label = label, Value = "" };
    private static ProtocolTreeNode Leaf(string label, string value, string fieldKey = "") => new() { Label = label, Value = value, FieldKey = fieldKey };
}
