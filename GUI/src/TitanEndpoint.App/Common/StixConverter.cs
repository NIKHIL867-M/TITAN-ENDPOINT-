using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TitanEndpoint.App.Common;

/// <summary>Converts the Correlator's own correlated_events.json (see
/// CORRELATOR\correlated_snapshot_writer.cpp) into a STIX 2.1 Bundle, so it can be handed to an
/// OpenCTI instance -- or any other STIX 2.1 consumer -- once one exists to receive it. Pure,
/// offline, local-file conversion only; nothing here talks to a network.
///
/// Deliberately emits only "observed-data" objects, never "indicator" objects: TITAN has watched
/// and recorded real activity with real evidence, but has not judged any of it malicious -- that
/// judgment belongs to whichever threat-intel platform compares these observables against its own
/// knowledge base (see TITAN_OPENCTI_INTEGRATION_PLAN.txt, "Design B"). Every field written here is
/// read verbatim from a real field already in correlated_events.json, or from a member event's own
/// raw_source; nothing is invented, guessed, or defaulted just to make an object "look complete".
/// An incident that produces zero real observables (e.g. a process-only session with no IP, file,
/// or hash) is skipped rather than exported empty -- STIX itself requires object_refs to be
/// non-empty, and a fabricated placeholder would violate the whole project's evidence-only rule.</summary>
public static class StixConverter
{
    // STIX 2.1 spec Appendix B: the fixed namespace UUID used to derive deterministic IDs for the
    // SCO types that define "id-contributing-properties" (ipv4-addr/ipv6-addr by value, file by
    // hash) -- so the same IP or the same file hash always gets the same STIX id across separate
    // conversion runs, letting a STIX consumer (OpenCTI included) merge repeats of the same real
    // indicator instead of seeing a fresh duplicate object every time this button is pressed.
    private static readonly Guid StixNamespace = Guid.Parse("00abedb4-aa42-466c-9c01-fed23315a9b7");

    public sealed class ConversionResult
    {
        public bool Success;
        public string? ErrorMessage;
        public string? BundleJson;
        public int IncidentsRead;
        public int IncidentsExported;
        public int IncidentsSkippedNoObservables;
        public int Ipv4Count;
        public int Ipv6Count;
        public int FileCount;
        public int FileWithHashCount;
        public int ProcessCount;
        public int NetworkTrafficCount;
        public int UsbDeviceCount;
        public int ObservedDataCount;
    }

    public static ConversionResult Convert(string correlatedEventsJsonPath)
    {
        var result = new ConversionResult();
        if (!File.Exists(correlatedEventsJsonPath))
        {
            result.ErrorMessage = $"No correlated_events.json found yet at {correlatedEventsJsonPath} -- " +
                "the Correlator only writes this file once it has seen at least one real correlated group.";
            return result;
        }

        JsonDocument doc;
        try
        {
            using var stream = File.OpenRead(correlatedEventsJsonPath);
            doc = JsonDocument.Parse(stream);
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Could not parse correlated_events.json: {ex.Message}";
            return result;
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("correlated_incidents", out var incidents) || incidents.ValueKind != JsonValueKind.Array)
            {
                result.ErrorMessage = "correlated_events.json has no correlated_incidents array -- nothing to convert.";
                return result;
            }

            var objects = new JsonArray();
            var ipv4Cache = new Dictionary<string, string>();
            var ipv6Cache = new Dictionary<string, string>();
            var fileByHashCache = new Dictionary<string, string>();
            var usbDeviceCache = new Dictionary<string, JsonObject>();

            foreach (var incident in incidents.EnumerateArray())
            {
                result.IncidentsRead++;
                var objectRefs = new List<string>();
                // Santosh, 2026-08-31 (second pass): "make sure that this bug should not come no more,
                // dropping anything in the stix." Full field-by-field re-audit against the live
                // correlated_events.json, not just re-confirming the src_ip fix. Found three more real
                // gaps beyond that one:
                //   1. This per-event network-traffic rewrite (see below) can, in rare cases, cover
                //      FEWER dest_ips than the incident-level aggregate did (confirmed: 2 real incidents
                //      where dest_ips had an IP with no matching per-event dst_ip -- a genuine regression
                //      risk from fixing gap #1 last time). coveredDestIps tracks what the per-event pass
                //      already emitted so the reconciliation pass after the events loop can still emit
                //      any aggregate IP that per-event coverage missed, matching the old code's coverage
                //      as a floor while keeping the new src_ref/ports/direction enrichment.
                //   2. 726 real "process" endpoint events (pid, parent_pid, command_line, path,
                //      user_name, user_sid, signature_valid -- all real, confirmed populated on a live
                //      svchost.exe example) were entirely ignored by this converter -- every process
                //      object in STIX had a bare name and nothing else, ever.
                //   3. "application" endpoint events (278 of them) were entirely ignored too -- and
                //      they are not a minor source: they carry real file-touch evidence (97 events,
                //      including cases the native File endpoint's own file_integrity sensor never saw)
                //      AND real process-attributed network connections (network_summary, via
                //      ip_helper_owner_pid_tables -- literally which process owned a connection, a
                //      stronger signal than the raw packet capture's src/dst alone).
                var coveredDestIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Shared by the native "network" endpoint and "application" endpoint's network_summary
                // sub-records -- both carry the identical src_ip/dst_ip/ports/protocol/direction shape,
                // and application's version additionally carries a real process_name/pid attribution the
                // raw packet capture cannot provide.
                void AddNetworkTrafficFromEvent(JsonElement ev)
                {
                    var srcIp = GetStr(ev, "src_ip");
                    var dstIp = GetStr(ev, "dst_ip");
                    var srcRef = string.IsNullOrWhiteSpace(srcIp) ? null : AddIpAddress(srcIp, objects, ipv4Cache, ipv6Cache, result);
                    var dstRef = string.IsNullOrWhiteSpace(dstIp) ? null : AddIpAddress(dstIp, objects, ipv4Cache, ipv6Cache, result);
                    if (srcRef != null) objectRefs.Add(srcRef);
                    if (dstRef != null) { objectRefs.Add(dstRef); coveredDestIps.Add(dstIp); }

                    var protocol = GetStr(ev, "protocol");
                    var expectedProtocol = GetStr(ev, "expected_protocol");
                    var direction = GetStr(ev, "direction");
                    var processName = GetStr(ev, "process_name");
                    var protocolMismatch = ev.TryGetProperty("protocol_mismatch", out var pmEl) && pmEl.ValueKind is JsonValueKind.True or JsonValueKind.False ? pmEl.GetBoolean() : (bool?)null;
                    var srcPort = ev.TryGetProperty("src_port", out var spEl) && spEl.ValueKind == JsonValueKind.Number && spEl.TryGetInt64(out var spVal) ? spVal : (long?)null;
                    var dstPort = ev.TryGetProperty("dst_port", out var dpEl) && dpEl.ValueKind == JsonValueKind.Number && dpEl.TryGetInt64(out var dpVal) ? dpVal : (long?)null;

                    if (srcRef == null && dstRef == null && srcPort == null && dstPort == null) return;

                    var ntId = "network-traffic--" + Guid.NewGuid();
                    var nt = new JsonObject
                    {
                        ["type"] = "network-traffic",
                        ["id"] = ntId,
                        ["protocols"] = new JsonArray(string.IsNullOrEmpty(protocol) ? (JsonNode?)JsonValue.Create("ip") : JsonValue.Create(protocol.ToLowerInvariant()))
                    };
                    if (srcRef != null) nt["src_ref"] = srcRef;
                    if (dstRef != null) nt["dst_ref"] = dstRef;
                    if (srcPort != null) nt["src_port"] = srcPort.Value;
                    if (dstPort != null) nt["dst_port"] = dstPort.Value;
                    if (!string.IsNullOrEmpty(direction)) nt["x_titan_direction"] = direction;
                    if (!string.IsNullOrEmpty(processName)) nt["x_titan_process_name"] = processName;
                    if (!string.IsNullOrEmpty(expectedProtocol)) nt["x_titan_expected_protocol"] = expectedProtocol;
                    if (protocolMismatch != null) nt["x_titan_protocol_mismatch"] = protocolMismatch.Value;
                    objects.Add(nt);
                    objectRefs.Add(ntId);
                    result.NetworkTrafficCount++;
                }

                // ---- Process observables, from the incident's own already-deduped process-name
                // set. No pid is attached here: the incident-level "processes" and "pids" arrays are
                // two separately deduped sets, so pairing an arbitrary pid with an arbitrary name
                // here would assert a link the source data does not actually establish. (A real,
                // verified pid<->process pairing for File-endpoint members is still attached below,
                // since that comes from one single real event record, not a cross-array guess.)
                foreach (var name in ReadStringArray(incident, "processes"))
                {
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    var procId = "process--" + Guid.NewGuid();
                    objects.Add(new JsonObject { ["type"] = "process", ["id"] = procId, ["name"] = name });
                    objectRefs.Add(procId);
                    result.ProcessCount++;
                }

                // ---- File observables: per real event, since hash/path are not aggregated at the
                // incident level (only the raw log filename is, in source_files[] -- which is a
                // different thing entirely: which .jsonl the record came from, not the file path
                // that was actually observed).
                if (incident.TryGetProperty("events", out var eventsEl) && eventsEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var ev in eventsEl.EnumerateArray())
                    {
                        var evEndpoint = GetStr(ev, "endpoint");

                        // ---- Network observables: src_ip/dst_ip/src_port/dst_port/protocol/direction
                        // are real flat fields already present directly on a "network" event (confirmed
                        // against NETOWRK ENDPOINT's own event shape) -- not aggregated, not guessed.
                        if (evEndpoint == "network")
                        {
                            AddNetworkTrafficFromEvent(ev);
                            continue;
                        }

                        // ---- Process observables: 726 real events confirmed carrying pid, parent_pid,
                        // command_line, path, user_name, user_sid and signature_valid directly as flat
                        // fields (not just inside raw_source) -- previously 100% ignored by this
                        // converter; only the bare incident-level process NAME (no pid/path/cmdline/
                        // user/signature) ever reached STIX. binary_ref reuses AddFile so the process's
                        // actual executable becomes a real, dedup'd file observable, same as any other
                        // file this converter records.
                        if (evEndpoint == "process")
                        {
                            var procName = GetStr(ev, "process_name");
                            var procPid = ev.TryGetProperty("pid", out var ppEl) && ppEl.ValueKind == JsonValueKind.Number && ppEl.TryGetInt64(out var ppVal) && ppVal > 0 ? ppVal : (long?)null;
                            if (string.IsNullOrWhiteSpace(procName) && procPid is null) continue; // nothing real to identify this process by

                            var procId = "process--" + Guid.NewGuid();
                            var procObj = new JsonObject { ["type"] = "process", ["id"] = procId };
                            if (!string.IsNullOrWhiteSpace(procName)) procObj["name"] = procName;
                            if (procPid != null) procObj["pid"] = procPid.Value;
                            var cmdLine = GetStr(ev, "command_line");
                            if (!string.IsNullOrWhiteSpace(cmdLine)) procObj["command_line"] = cmdLine;
                            var evPath = GetStr(ev, "path");
                            if (!string.IsNullOrWhiteSpace(evPath))
                            {
                                var binRef = AddFile(evPath, "", objects, fileByHashCache, result);
                                procObj["binary_ref"] = binRef;
                                objectRefs.Add(binRef);
                            }
                            var parentPid = ev.TryGetProperty("parent_pid", out var parEl) && parEl.ValueKind == JsonValueKind.Number && parEl.TryGetInt64(out var parVal) && parVal > 0 ? parVal : (long?)null;
                            if (parentPid != null) procObj["x_titan_parent_pid"] = parentPid.Value;
                            var userName = GetStr(ev, "user_name");
                            if (!string.IsNullOrWhiteSpace(userName)) procObj["x_titan_user"] = userName;
                            var userSid = GetStr(ev, "user_sid");
                            if (!string.IsNullOrWhiteSpace(userSid)) procObj["x_titan_user_sid"] = userSid;
                            if (ev.TryGetProperty("signature_valid", out var sigEl) && sigEl.ValueKind is JsonValueKind.True or JsonValueKind.False)
                                procObj["x_titan_signature_valid"] = sigEl.GetBoolean();
                            var procRecordType = GetStr(ev, "record_type");
                            if (!string.IsNullOrWhiteSpace(procRecordType)) procObj["x_titan_record_type"] = procRecordType;

                            objects.Add(procObj);
                            objectRefs.Add(procId);
                            result.ProcessCount++;
                            continue;
                        }

                        // ---- Application-endpoint observables: this endpoint multiplexes three real
                        // record shapes (confirmed live: "file", "network_summary", "repeat_summary")
                        // under one "application" tag, branching on which real fields are actually
                        // present rather than trusting record_type's exact string (repeat_summary wraps
                        // either a file or network observation and was found to still carry path/
                        // src_ip/dst_ip directly). Genuinely new evidence, not a duplicate of the native
                        // File/Network endpoints -- confirmed 97 real file-touch events and 3 real
                        // process-attributed connections (ip_helper_owner_pid_tables) that the native
                        // sensors do not themselves capture.
                        if (evEndpoint == "application")
                        {
                            var appDstIp = GetStr(ev, "dst_ip");
                            if (!string.IsNullOrWhiteSpace(appDstIp)) { AddNetworkTrafficFromEvent(ev); continue; }

                            var appPath = GetStr(ev, "path");
                            // "unresolved" is a real literal value the endpoint itself writes when it
                            // could not map a file handle back to a path -- confirmed live, not a bug --
                            // exporting it as a STIX file name/path would fabricate a fake observable
                            // where the source honestly reported "not known", so it is skipped here
                            // exactly like an empty path, never invented into a file object.
                            if (!string.IsNullOrWhiteSpace(appPath) && !appPath.Equals("unresolved", StringComparison.OrdinalIgnoreCase))
                                objectRefs.Add(AddFile(appPath, "", objects, fileByHashCache, result));

                            var appProc = GetStr(ev, "process_name");
                            if (!string.IsNullOrWhiteSpace(appProc))
                            {
                                var appPidVal = ev.TryGetProperty("pid", out var appPidEl) && appPidEl.ValueKind == JsonValueKind.Number && appPidEl.TryGetInt64(out var apv) && apv > 0 ? apv : (long?)null;
                                var appProcId = "process--" + Guid.NewGuid();
                                var appProcObj = new JsonObject { ["type"] = "process", ["id"] = appProcId, ["name"] = appProc };
                                if (appPidVal != null) appProcObj["pid"] = appPidVal.Value;
                                objects.Add(appProcObj);
                                objectRefs.Add(appProcId);
                                result.ProcessCount++;
                            }
                            continue;
                        }

                        // ---- USB/Port observables: the endpoint's raw records come in three
                        // different real shapes (confirmed by reading PORT ENDPOINT\src_usb\
                        // usb_monitor.cpp / usb_session.cpp directly, not assumed) -- arrival
                        // telemetry and the injection-timing alert carry vid/pid/manufacturer/
                        // product/instance_id at the TOP level, while the end-of-session summary
                        // nests the same identity fields under "device":{...} instead, alongside
                        // mount_point and a real reads/writes/bytes activity summary at its own
                        // top level. AddUsbDevice tries both shapes so either kind of record is
                        // captured, and only ever includes a field that is actually present.
                        if (evEndpoint == "port")
                        {
                            var rawSourcePort = GetStr(ev, "raw_source");
                            if (!string.IsNullOrEmpty(rawSourcePort))
                            {
                                try
                                {
                                    using var rawDoc = JsonDocument.Parse(rawSourcePort);
                                    var deviceId = AddUsbDevice(rawDoc.RootElement, objects, usbDeviceCache, result);
                                    if (deviceId != null) objectRefs.Add(deviceId);
                                }
                                catch (JsonException) { /* raw_source not parseable -- nothing to add for this event */ }
                            }
                            continue;
                        }

                        if (evEndpoint != "file_integrity") continue;
                        var path = GetStr(ev, "path");
                        var rawSource = GetStr(ev, "raw_source");
                        var hash = "";
                        var procFromFile = "";
                        if (!string.IsNullOrEmpty(rawSource))
                        {
                            try
                            {
                                using var rawDoc = JsonDocument.Parse(rawSource);
                                var root = rawDoc.RootElement;
                                if (root.TryGetProperty("current_sha256", out var h1) && h1.ValueKind == JsonValueKind.String) hash = h1.GetString() ?? "";
                                else if (root.TryGetProperty("sha256", out var h2) && h2.ValueKind == JsonValueKind.String) hash = h2.GetString() ?? "";
                                if (root.TryGetProperty("process", out var pr) && pr.ValueKind == JsonValueKind.String) procFromFile = pr.GetString() ?? "";
                            }
                            catch (JsonException) { /* raw_source not parseable -- path/name below still work without it */ }
                        }

                        if (!string.IsNullOrWhiteSpace(path))
                            objectRefs.Add(AddFile(path, hash, objects, fileByHashCache, result));

                        if (!string.IsNullOrWhiteSpace(procFromFile))
                        {
                            long? pidVal = ev.TryGetProperty("pid", out var pidEl) && pidEl.ValueKind == JsonValueKind.Number && pidEl.TryGetInt64(out var pv) ? pv : null;
                            var procId = "process--" + Guid.NewGuid();
                            var procObj = new JsonObject { ["type"] = "process", ["id"] = procId, ["name"] = procFromFile };
                            if (pidVal is > 0) procObj["pid"] = pidVal.Value;
                            objects.Add(procObj);
                            objectRefs.Add(procId);
                            result.ProcessCount++;
                        }
                    }
                }

                // ---- Reconciliation: the incident-level "dest_ips" aggregate is confirmed (live data)
                // to occasionally contain an IP with no matching per-event dst_ip in this incident's own
                // events[] (2 real cases found in the 2026-08-31 audit -- likely a repeat/compaction
                // case where the aggregate kept more distinct IPs than individual event records were
                // retained for). The per-event pass above is strictly richer when it has a matching
                // event (src_ref, ports, direction, process_name), so it always wins; this only ever
                // ADDS an IP the per-event pass genuinely missed, as a bare address with no fabricated
                // connection details attached, so the old code's coverage is a guaranteed floor.
                foreach (var leftoverIp in ReadStringArray(incident, "dest_ips"))
                {
                    if (coveredDestIps.Contains(leftoverIp)) continue;
                    var refId = AddIpAddress(leftoverIp, objects, ipv4Cache, ipv6Cache, result);
                    if (refId != null) { objectRefs.Add(refId); coveredDestIps.Add(leftoverIp); }
                }

                objectRefs = objectRefs.Distinct().ToList();
                if (objectRefs.Count == 0) { result.IncidentsSkippedNoObservables++; continue; }

                var corrId = GetStr(incident, "corr_id");
                var corrType = GetStr(incident, "corr_type");
                var startTs = GetStr(incident, "start_ts");
                var endTs = GetStr(incident, "end_ts");
                var numberObserved = incident.TryGetProperty("total_occurrences", out var occ) && occ.ValueKind == JsonValueKind.Number && occ.TryGetInt64(out var ov) ? Math.Max(1, ov) : 1;
                var nowIso = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

                var od = new JsonObject
                {
                    ["type"] = "observed-data",
                    ["id"] = "observed-data--" + Guid.NewGuid(),
                    ["created"] = nowIso,
                    ["modified"] = nowIso,
                    ["first_observed"] = string.IsNullOrEmpty(startTs) ? nowIso : startTs,
                    ["last_observed"] = string.IsNullOrEmpty(endTs) ? (string.IsNullOrEmpty(startTs) ? nowIso : startTs) : endTs,
                    ["number_observed"] = numberObserved,
                    ["object_refs"] = new JsonArray(objectRefs.Select(r => (JsonNode?)JsonValue.Create(r)).ToArray()),
                    ["labels"] = new JsonArray((JsonNode?)JsonValue.Create($"titan-corr-id:{corrId}"), (JsonNode?)JsonValue.Create($"titan-corr-type:{corrType}")),
                    ["x_titan_corr_id"] = corrId,
                    ["x_titan_corr_type"] = corrType,
                    ["x_titan_summary"] = GetStr(incident, "summary"),
                    ["x_titan_confidence_summary"] = GetStr(incident, "confidence_summary")
                };

                // Santosh, 2026-08-13: "make sure that all the correlated data should properly and
                // cleanly converted into the STIX, so that no data loss should be there." Audited
                // every field CorrelatedSnapshotWriter emits per incident (correlated_snapshot_writer
                // .cpp's RenderDocument) against what this converter actually carried into STIX --
                // these five were real fields that existed in the source and were silently never
                // written anywhere in the STIX output. Added as x_titan_* custom properties (the
                // same convention already used above) rather than restructured into new SCO/SDO
                // types, since none of them are themselves standalone observables -- they are all
                // incident-level facts about the SAME correlated group the observed-data object
                // already represents.
                var users = ReadStringArray(incident, "users");
                if (users.Count > 0) od["x_titan_users"] = new JsonArray(users.Select(u => (JsonNode?)JsonValue.Create(u)).ToArray());
                var recordTypes = ReadStringArray(incident, "record_types");
                if (recordTypes.Count > 0) od["x_titan_record_types"] = new JsonArray(recordTypes.Select(r => (JsonNode?)JsonValue.Create(r)).ToArray());
                if (incident.TryGetProperty("connected", out var connectedEl) && connectedEl.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    od["x_titan_connected"] = connectedEl.GetBoolean();
                if (incident.TryGetProperty("unique_events", out var uniqueEl) && uniqueEl.ValueKind == JsonValueKind.Number && uniqueEl.TryGetInt64(out var uniqueVal))
                    od["x_titan_unique_events"] = uniqueVal;
                if (incident.TryGetProperty("duration_seconds", out var durEl) && durEl.ValueKind == JsonValueKind.Number && durEl.TryGetDouble(out var durVal))
                    od["x_titan_duration_seconds"] = durVal;

                // The single biggest real gap found in the audit: "connections[]" -- the actual
                // record of WHICH member events joined to WHICH others, WHY (same_pid/
                // parent_child_pid/usb_mount_path_match/etc.), and at what confidence -- is the exact
                // "which and all are related" reasoning data, and none of it reached STIX before this.
                // Kept as one custom array on the observed-data object rather than restructured into
                // formal STIX "relationship" objects: this converter aggregates/dedupes observables
                // across the whole incident (e.g. many file events collapsing into one file-by-hash
                // object), so the source's own from_event_index/to_event_index no longer map 1:1 onto
                // a single object_ref the way a relationship object requires -- preserving the real
                // reasoning losslessly here is correct and safe; silently dropping it, as before, was
                // the actual data loss.
                if (incident.TryGetProperty("connections", out var connectionsEl) && connectionsEl.ValueKind == JsonValueKind.Array)
                {
                    var connectionsOut = new JsonArray();
                    foreach (var conn in connectionsEl.EnumerateArray())
                    {
                        var connObj = new JsonObject();
                        if (conn.TryGetProperty("from_event_index", out var fe) && fe.ValueKind == JsonValueKind.Number) connObj["from_event_index"] = fe.GetInt32();
                        if (conn.TryGetProperty("to_event_index", out var te) && te.ValueKind == JsonValueKind.Number) connObj["to_event_index"] = te.GetInt32();
                        var reason = GetStr(conn, "reason");
                        if (!string.IsNullOrEmpty(reason)) connObj["reason"] = reason;
                        var confidence = GetStr(conn, "confidence");
                        if (!string.IsNullOrEmpty(confidence)) connObj["confidence"] = confidence;
                        if (conn.TryGetProperty("confidence_score", out var cs) && cs.ValueKind == JsonValueKind.Number && cs.TryGetDouble(out var csVal)) connObj["confidence_score"] = csVal;
                        if (conn.TryGetProperty("delta_ms", out var dm) && dm.ValueKind == JsonValueKind.Number) connObj["delta_ms"] = dm.GetInt64();
                        var matchedFields = ReadStringArray(conn, "matched_fields");
                        if (matchedFields.Count > 0) connObj["matched_fields"] = new JsonArray(matchedFields.Select(m => (JsonNode?)JsonValue.Create(m)).ToArray());
                        var caveat = GetStr(conn, "caveat");
                        if (!string.IsNullOrEmpty(caveat)) connObj["caveat"] = caveat;
                        connectionsOut.Add(connObj);
                    }
                    if (connectionsOut.Count > 0) od["x_titan_connections"] = connectionsOut;
                }

                objects.Add(od);
                result.ObservedDataCount++;
                result.IncidentsExported++;
            }

            var bundle = new JsonObject
            {
                ["type"] = "bundle",
                ["id"] = "bundle--" + Guid.NewGuid(),
                // STIX 2.1 §4.1: spec_version is a required Bundle property. Its absence made
                // every export technically non-conformant STIX 2.1 despite the feature's own
                // stated purpose -- a spec-conformant consumer (OpenCTI included) can reject a
                // bundle missing it.
                ["spec_version"] = "2.1",
                ["objects"] = objects
            };

            result.Success = true;
            result.BundleJson = bundle.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            return result;
        }
    }

    private static string GetStr(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static List<string> ReadStringArray(JsonElement el, string prop)
    {
        var list = new List<string>();
        if (el.TryGetProperty(prop, out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var item in arr.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString() ?? "");
        return list;
    }

    private static string? AddIpAddress(string ip, JsonArray objects, Dictionary<string, string> ipv4Cache,
        Dictionary<string, string> ipv6Cache, ConversionResult result)
    {
        if (!IPAddress.TryParse(ip, out var parsed)) return null;

        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            if (ipv4Cache.TryGetValue(ip, out var existing)) return existing;
            var id = "ipv4-addr--" + Uuid5(StixNamespace, "{\"value\":\"" + ip + "\"}");
            objects.Add(new JsonObject { ["type"] = "ipv4-addr", ["id"] = id, ["value"] = ip });
            ipv4Cache[ip] = id;
            result.Ipv4Count++;
            return id;
        }
        if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipv6Cache.TryGetValue(ip, out var existing)) return existing;
            var id = "ipv6-addr--" + Uuid5(StixNamespace, "{\"value\":\"" + ip + "\"}");
            objects.Add(new JsonObject { ["type"] = "ipv6-addr", ["id"] = id, ["value"] = ip });
            ipv6Cache[ip] = id;
            result.Ipv6Count++;
            return id;
        }
        return null;
    }

    private static string AddFile(string path, string sha256, JsonArray objects,
        Dictionary<string, string> fileByHashCache, ConversionResult result)
    {
        var name = path.Replace('/', '\\').Split('\\').LastOrDefault(s => s.Length > 0) ?? path;

        if (!string.IsNullOrEmpty(sha256))
        {
            var normalizedHash = sha256.ToLowerInvariant();
            if (fileByHashCache.TryGetValue(normalizedHash, out var existing)) return existing;
            var id = "file--" + Uuid5(StixNamespace, "{\"hashes\":{\"SHA-256\":\"" + normalizedHash + "\"}}");
            objects.Add(new JsonObject
            {
                ["type"] = "file",
                ["id"] = id,
                ["name"] = name,
                ["hashes"] = new JsonObject { ["SHA-256"] = normalizedHash },
                ["x_titan_full_path"] = path
            });
            fileByHashCache[normalizedHash] = id;
            result.FileCount++;
            result.FileWithHashCount++;
            return id;
        }

        // No hash available for this file (hashing only runs for executable/document/protected
        // paths -- see FILEEE\file_processor.cpp's ApplyHashEvidence) -- still export the observable
        // by name/path so nothing actually seen is silently dropped, just without deterministic
        // dedup (STIX defines no id-contributing-property for a hash-less file, so a fresh id here
        // is spec-correct, not a shortcut).
        var randomId = "file--" + Guid.NewGuid();
        objects.Add(new JsonObject { ["type"] = "file", ["id"] = randomId, ["name"] = name, ["x_titan_full_path"] = path });
        result.FileCount++;
        return randomId;
    }

    // STIX 2.1 has no built-in "USB device" object type, so this uses a custom object (the "x-"
    // type-name prefix is the one part of a custom object STIX itself requires -- see spec section
    // 7.3). Identity fields are read from EITHER of the two real shapes the Port/USB endpoint
    // actually emits: top-level (usb_hid_event / usb_injection_alert) or nested under "device"
    // (the end-of-session summary) -- confirmed directly from PORT ENDPOINT\src_usb\usb_monitor.cpp
    // and usb_session.cpp, not assumed. A field simply stays absent from the object if the source
    // record didn't carry it; nothing here is a guessed or default value.
    private static string? AddUsbDevice(JsonElement root, JsonArray objects,
        Dictionary<string, JsonObject> deviceCache, ConversionResult result)
    {
        root.TryGetProperty("device", out var deviceEl);
        var hasDevice = deviceEl.ValueKind == JsonValueKind.Object;

        string Field(string name) =>
            (hasDevice && deviceEl.TryGetProperty(name, out var nested) && nested.ValueKind == JsonValueKind.String ? nested.GetString() : null)
            ?? (root.TryGetProperty(name, out var top) && top.ValueKind == JsonValueKind.String ? top.GetString() : null)
            ?? "";

        var vid = Field("vid");
        var pid = Field("pid");
        var serial = Field("serial");
        var manufacturer = Field("manufacturer");
        var product = Field("product");
        var instanceId = Field("instance_id");
        var mountPoint = root.TryGetProperty("mount_point", out var mp) && mp.ValueKind == JsonValueKind.String ? mp.GetString() ?? "" : "";

        if (string.IsNullOrEmpty(vid) && string.IsNullOrEmpty(pid) && string.IsNullOrEmpty(serial) &&
            string.IsNullOrEmpty(instanceId) && string.IsNullOrEmpty(mountPoint))
            return null; // nothing real to identify this device by -- do not emit an empty/guessed object

        // The three real record shapes this endpoint emits do not all carry the same identity
        // fields -- arrival/injection-alert telemetry has no serial number, only the end-of-session
        // summary does (confirmed directly from usb_monitor.cpp / usb_session.cpp). Try BOTH
        // possible keys for an existing object before creating a new one, so a later, richer record
        // for a device already seen from a sparser earlier record still merges into the same object
        // instead of creating a duplicate.
        JsonObject? existing = null;
        if (!string.IsNullOrEmpty(serial)) deviceCache.TryGetValue("serial:" + serial, out existing);
        if (existing is null && !string.IsNullOrEmpty(instanceId)) deviceCache.TryGetValue("instance:" + instanceId, out existing);

        JsonObject obj;
        if (existing is not null)
        {
            obj = existing;
        }
        else
        {
            obj = new JsonObject { ["type"] = "x-titan-usb-device", ["id"] = "x-titan-usb-device--" + Guid.NewGuid() };
            objects.Add(obj);
            result.UsbDeviceCount++;
        }

        // Register/refresh both lookup keys against this object -- once a device's serial becomes
        // known (from a later, richer record) an earlier record for the same device that only had
        // an instance id is still found and merged into, not duplicated. First real value for a
        // given field wins; a field is only ever filled in, never overwritten with a blank.
        if (!string.IsNullOrEmpty(serial)) deviceCache["serial:" + serial] = obj;
        if (!string.IsNullOrEmpty(instanceId)) deviceCache["instance:" + instanceId] = obj;

        void SetIfAbsent(string key, string value)
        {
            if (!string.IsNullOrEmpty(value) && obj[key] is null) obj[key] = value;
        }
        SetIfAbsent("vid", vid);
        SetIfAbsent("pid", pid);
        SetIfAbsent("serial", serial);
        SetIfAbsent("manufacturer", manufacturer);
        SetIfAbsent("product", product);
        SetIfAbsent("instance_id", instanceId);
        SetIfAbsent("mount_point", mountPoint);

        // Real activity summary, only present on the end-of-session record -- genuinely relevant to
        // an analyst (was this device used to move files) so it is carried through rather than
        // dropped, but only ever the fields that are actually there.
        if (obj["activity_summary"] is null && root.TryGetProperty("activity", out var activity) && activity.ValueKind == JsonValueKind.Object)
        {
            var activityObj = new JsonObject();
            foreach (var key in new[] { "reads", "writes", "deletes", "executes", "bytes_read", "bytes_written" })
                if (activity.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var lv))
                    activityObj[key] = lv;
            if (activityObj.Count > 0) obj["activity_summary"] = activityObj;
        }

        // Real keystroke-injection timing evidence, only present on a usb_injection_alert record --
        // carried through as-is (never re-labelled "malicious"; TITAN observed timing evidence, it
        // did not itself declare an attack -- same evidence-only rule as everywhere else here).
        if (obj["hid_injection_suspected"] is null && root.TryGetProperty("hid_injection_suspected", out var suspected) &&
            suspected.ValueKind is JsonValueKind.True or JsonValueKind.False)
            obj["hid_injection_suspected"] = suspected.GetBoolean();

        return (string)obj["id"]!;
    }

    // Standard RFC 4122 UUIDv5 (name-based, SHA-1) generation, adapted for .NET's Guid byte layout
    // (the first three fields are stored little-endian internally but must be hashed big-endian).
    private static string Uuid5(Guid namespaceId, string name)
    {
        var nsBytes = namespaceId.ToByteArray();
        SwapByteOrder(nsBytes);
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var combined = new byte[nsBytes.Length + nameBytes.Length];
        Buffer.BlockCopy(nsBytes, 0, combined, 0, nsBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, combined, nsBytes.Length, nameBytes.Length);

        var hash = SHA1.HashData(combined);
        var newGuid = new byte[16];
        Array.Copy(hash, 0, newGuid, 0, 16);
        newGuid[6] = (byte)((newGuid[6] & 0x0F) | 0x50); // version 5
        newGuid[8] = (byte)((newGuid[8] & 0x3F) | 0x80); // RFC 4122 variant
        SwapByteOrder(newGuid);
        return new Guid(newGuid).ToString();
    }

    private static void SwapByteOrder(byte[] guid)
    {
        SwapBytes(guid, 0, 3); SwapBytes(guid, 1, 2);
        SwapBytes(guid, 4, 5);
        SwapBytes(guid, 6, 7);
    }

    private static void SwapBytes(byte[] guid, int left, int right) => (guid[left], guid[right]) = (guid[right], guid[left]);
}
