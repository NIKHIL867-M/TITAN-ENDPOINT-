using TitanEndpoint.App.ViewModels;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.UiTests;

internal static class UnifiedCorrelationSchemaTests
{
    public static List<string> Run()
    {
        var failures = new List<string>();
        void Check(bool condition, string name)
        {
            Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
            if (!condition) failures.Add(name);
        }

        const string connectedJson = """
            {"type":"unified_event","t_unix_ms":1000,"group_id":42,"event_count":4,"unique_event_count":2,"repeat_count":2,"source_count":2,"sources":["process","network"],"correlation":{"connected":true},"events":[{"endpoint":"process","record_type":"process_start","t_unix_ms":900,"last_seen":900,"repeat_count":1,"pid":123,"parent_pid":10,"raw_source":"{\"pid\":123}"},{"endpoint":"network","record_type":"network_packet","t_unix_ms":1000,"last_seen":1100,"repeat_count":3,"pid":123,"parent_pid":0,"raw_source":"{\"pid\":123}"}],"connections":[{"from":0,"to":1,"reason":"same_pid","matched_fields":["pid"],"delta_ms":100,"window_ms":2000,"confidence":"high","confidence_score":0.93}]}
            """;
        var record = JsonRecord.TryParse(connectedJson, DateTimeOffset.UtcNow);
        var row = record is null ? null : CorrelationRowViewModel.From(record, null);
        Check(row is not null, "unified_event parses into a dashboard row");
        Check(row?.RecordCount == 4 && row.MemberCount == 2 && row.RepeatCount == 2,
            "record, unique and compacted-repeat counts stay distinct");
        Check(row?.Connections.Count == 1 && row.Connections[0].FromIndex == 0 && row.Connections[0].ToIndex == 1,
            "real engine connection indexes drive the graph");
        Check(row?.MissingEndpointsText.Contains("Connected 2 sources", StringComparison.Ordinal) == true &&
              !row.MissingEndpointsText.Contains("of 5", StringComparison.Ordinal),
            "row describes actual participants instead of misleading missing-source coverage");
        Check(row?.Members[1].RepeatText == "3x compacted", "member repeat aggregation is visible");

        const string singleJson = """
            {"type":"unified_event","t_unix_ms":2000,"group_id":43,"event_count":1,"repeat_count":0,"events":[{"endpoint":"file_integrity","record_type":"write","t_unix_ms":2000,"repeat_count":1,"pid":9,"raw_source":"{}"}],"connections":[]}
            """;
        var singleRecord = JsonRecord.TryParse(singleJson, DateTimeOffset.UtcNow);
        var single = singleRecord is null ? null : CorrelationRowViewModel.From(singleRecord, null);
        Check(single?.Connections.Count == 0 && single.MissingEndpointsText.Contains("Single-source", StringComparison.Ordinal),
            "unmatched evidence remains visible and explicitly labeled");

        return failures;
    }
}
