# TITAN ENDPOINT — Logs and Endpoint Reference

*Structured in two parts, as requested: Part 1 inventories every distinct log/evidence file this
project produces — what it is, where it lives, and its real key fields. Part 2 explains each
endpoint's actual features and internal logic, separately. Field names below are taken directly
from real on-disk log samples and the native/Python source that produces them, not guessed.*

---

# PART 1 — Log and Evidence File Inventory

## 1.1 Port (USB) — `usb_events.json` (+ rotated archives)

- **Location**: `C:\ProgramData\TitanUSB\logs\` (fixed path, independent of where `usb_test.exe`
  is launched from).
- **What it's for**: every USB device arrival/removal, HID-keyboard-specific arrival, storage
  session activity summary, and HID-injection timing verdict.
- **Record types**: `usb_session` (storage device, arrival→removal lifecycle with file-activity
  anomaly flags), `usb_hid_event` (HID keyboard arrival), `usb_injection_alert` (keystroke-timing
  verdict), `collector_health`.
- **Key fields observed**: `event_type` (e.g. `USB_DEVICE_ARRIVED`, `USB_HID_KEYBOARD_ARRIVED`,
  `USB_SESSION_END`), `vid`/`pid` (also nested under a `device` object on some records), `product`,
  `manufacturer`, `mount_point`, `session_id`/`instance_id`, and for HID-injection verdicts:
  `hid_injection_suspected`, `mean_interval_ms`, `stddev_interval_ms`, `sample_count`. A session-end
  record carries a nested `activity` object with `reads`/`writes`/`bytes_written`.

## 1.2 Process — `titan_*.jsonl` packs

- **Location**: configured relative to the exe's working directory (per `runtime-manifest.json`,
  currently `PROCESS ENDPOINT\titan_fixed\out\build\release-manifest\bin\logs\`).
- **What it's for**: every process start/lifecycle snapshot the ETW Kernel-Process provider
  reports, enriched with signature/trust/persistence/parent-child context.
- **Record types**: process events (`event_subtype: "process_snapshot"` — the collector emits
  periodic point-in-time snapshots, not discrete start/stop events), `collector_health`,
  `control_audit` (every IPC control-channel mutation, accepted or rejected, for accountability).
- **Key fields**: `pid`, `process_name`, `canonical_path`, `image_path_raw`, `command_line_raw` /
  `cmdline_normalized`, `parent_pid`, `real_parent_pid`, `location_type` (`SYSTEM` / `KNOWN_USER` —
  trust classification from the 7-stage filter), `signature_valid`, `signature_signer`,
  `child_count`, `unique_child_names`, `new_child_flag`, `fingerprint`, `user_name`, `user_sid`,
  `elevation`, `integrity` (Windows integrity level), `is_64bit`, `process_start_time`.
- **Durable evidence envelope** (present on every line, stamped by the shared logging choke point):
  `record_id`, `session_id`, `source_file`, `byte_offset`, `content_hash`.

## 1.3 File Integrity — `fim_events.json` (+ rotated archives)

- **Location**: `FILEEE\out\build\release-manifest\bin\Release\logs\` (per `runtime-manifest.json`).
- **What it's for**: file create/write/rename/delete activity classified as normal (SHA-256
  baselined), temp (bounded lifecycle-tracked, only promoted to durable evidence if it becomes/
  touches an executable target), protected, or excluded.
- **Record types**: normal file events (with hash/baseline comparison state), `temp_*` events (only
  for temp activity that's interesting enough to promote — short uninteresting temp churn is
  suppressed by design), `collector_health`.
- **Key fields**: `action`/`target_action`, `path`/`target_path`/`temp_path`, `process`/`creator`,
  `pid`/`creator_pid`, `hash_status` or `content_changed` (baseline comparison result), old/new path
  pairs for renames.

## 1.4 Network — `titan_*.jsonl` packs + `raw_pcap\*.pcap`

- **Location**: `NETOWRK ENDPOINT\out\build\release-manifest\logs\` (JSONL) and
  `...\logs\raw_pcap\adapter_<id>_<slot>.pcap` (raw frames — genuinely retained original bytes, not
  a summary, but **not currently offset-linked** back to individual JSONL records — a documented,
  honest gap, not a bug).
- **What it's for**: every parsed packet/flow with wire-level metadata plus best-effort local
  PID/process attribution.
- **Record type**: `network_packet` (`source: "npcap_live"`).
- **Key fields**: `pid`, `process_name`, `local_ip`/`local_port`, `remote_ip`/`remote_port`,
  `packet_src_ip`/`packet_dst_ip`, `adapter`, `capture_epoch_us`, `ether_type`,
  `transport_protocol`, `protocol`, `ipv6`, `direction` (`INBOUND`/`OUTBOUND` — a real,
  packet-derived value, not inferred), `state`, `bytes_sent`/`bytes_recv`, `packet_count`,
  `flow_duration_ms`, `captured_length`/`wire_length`, `raw_capture_mapped`/`raw_capture_segment`
  (which `.pcap` file, if any), fragmentation fields (`fragmented`/`fragment_offset`/
  `more_fragments`), `vlan_ids`, `is_broadcast`/`is_loopback`. Application-layer decode, when
  present: `dns_query`/`dns_query_type`/`dns_answers`, `tls_sni` (ClientHello SNI only),
  `http_method`/`http_target`/`http_host`/`http_status_code`/`http_reason`.

## 1.5 Application — `application_events.jsonl` (+ rotated archives)

- **Location**: `APP\out\build\release-manifest\bin\logs\` (per `runtime-manifest.json`).
- **What it's for**: activity from user-selected watched applications (up to 20) and their child
  processes — file access, network socket state, and decoded PowerShell/WMI/Defender/Security
  event-log activity.
- **Two record shapes** depending on source:
  1. **Watchlist events** (`type`: `process`/`file`/`application_state`/`selection`/`network`/
     `module`): `application`, `action`, `pid`, `tid`, `path`, `process_name`, `command_line`,
     `process_role`, `parent_pid`; for network specifically: `protocol` (`tcp4`/`tcp6`/`udp4`/
     `udp6`), `local_endpoint`, `remote_endpoint` (empty when the app is only listening/bound, not
     connected — `action` is `bind` in that case, `endpoint_observed` otherwise), `connection_state`
     (TCP state name).
  2. **Decoded event-log events** (`type`: `application_log`): `source`, `event_id`, `summary`,
     `script_content`/`script_path` (PowerShell), `network_activity` (URLs extracted from script
     content), `pattern_hits`, and boolean detection flags `credential_access`/`amsi_bypass`/
     `process_injection`.
- Plus `collector_health`.

## 1.6 Correlator — `correlator_*.jsonl`

- **Location**: `CORRELATOR\out\build\release-manifest\bin\logs\` (next to `correlator.exe`).
- **What it's for**: the only cross-endpoint evidence in the native layer — records that two or
  more of the 5 sensors' observations belong to the same real-world activity.
- **Record type**: `session_timeline` (one line per **revision** as a group grows, plus a final
  `"final": true` line at expiry — not one line per unique group), `collector_health`.
- **Key fields**: `group_id`, `revision`, `final`, `member_count`, `members[]` — each member carries
  `endpoint`, `record_type`, `t_unix_ms`, `pid`/`parent_pid`, `source_evidence_id`, join metadata
  (`join_reason`, `matched_fields`, `delta_ms`, `window_ms`, `confidence`, `confidence_score`), and
  — when the source endpoint has stamped one — the exact durable reference back to the original
  record: `native_record_id`, `native_session_id`, `native_source_file`, `native_byte_offset`, and
  (as of this session) `native_content_hash`, plus an embedded `raw_source` copy of the original
  line for display even if the source file has since rotated away.
- **Verified live**: a real byte-offset reference in a real `session_timeline` record was checked
  directly against the referenced Process-endpoint log file — the exact byte offset began exactly
  with the exact referenced `record_id`. The join/byte-offset pipeline is genuinely correct, not
  just structurally present.

## 1.7 CUSTOM RULE — several files under `CUSTOM RULE\data\`

| File | What it is | Key fields |
|---|---|---|
| `rules.jsonl` | Every **approved** rule (append-only, O(1) appends). Never contains rejected/draft rules. | `id`, `status`, `created_at`, `rule_text` (the original human input), `ir.ir` (the full structured RuleIR: `trigger_event`, `conditions[]`, `aggregation`/`correlation`/`sustain_for` (mutually exclusive), `response_actions[]` (`{type, duration}` — `type` is `alert`/`kill_process`/`isolate_host`), `severity`, `priority`, `tags[]`, `suggested_action[]`), `original_ir` (pre-edit copy if the rule was hand-edited before approval). |
| `alerts.jsonl` | Every alert a matched, approved rule actually produced. **Only written on a real condition match** — this is a deliberate storage policy (`unmatched_events: "transient_only"`), not a gap. | `id`, `instance_id`, `rule_id`, `rule_text`, `severity`, `fired_at`, `event_type`, `host`, `summary`, `action_results[]` (`{action, pid?, host?, result, at}` — `result` is the real outcome, e.g. `"alerted"`, `"dry_run"`, `"killed"`, `"self_isolation_blocked"`), `evidence_path`, `dry_run`, `_integrity` (HMAC-SHA256 tamper-check block). |
| `evidence\<uuid>.json` | Full investigation evidence for one alert instance (process tree, live network connections, etc. — depth varies by event type). Referenced by `alerts.jsonl`'s `evidence_path`. | Content varies by event type; always keyed to one `instance_id`. |
| `watcher_runtime.json` | The watcher's own live heartbeat/state file, rewritten periodically while running. | `state` (`watching`/`paused`/...), `rules_loaded`, `dry_run`, `pid`, `heartbeat_at`. The GUI/API independently compute `heartbeat_age_s` and treat anything older than ~15–60s as **stale**, never trusted as "currently watching." |
| `watcher.pid` | Lock file naming the authoritative watcher PID (a `python -m watcher.main` launch can show as two OS processes — a venv launcher stub plus the real interpreter child — this file, not the raw process list, says which one is real). | Just a PID. |
| watcher-activity store (served via `/api/watcher-activity`) | Bounded, sanitized diagnostic feed proving whether a real event was *observed*, *matched a rule*, and *saved* — without retaining full unmatched raw logs. | `kind` (`event_observed`/`rule_matched`/`alert_saved`/`event_deduplicated`/`rules_reloaded`/`sustain_pending`/`sustain_verified`/`sustain_not_met`/`rule_reload_degraded`), `at`, `event_type`, `rule_id`, `repeat_count`, `subject`/`process_name`/`pid`, `collector`. |
| collector-status store (backs `/api/watcher-capabilities`) | Live availability per collector/event type — which of the ~11 collectors are actually active right now vs. configured-but-failed (e.g. Sysmon reporting "not installed"). | `active_collectors[]`, `failed_collectors{name: reason}`, `configured_collectors[]`, `collector_details[]` (collection mode, poll interval). |

## 1.8 GUI-side logs

The GUI does not maintain its own separate evidence log — it tails every file above directly
(`LogTailer`, one instance per endpoint) and calls CUSTOM RULE's API for anything that needs a live
query. Its own "Diagnostics" panel per endpoint is a **bounded in-memory ring of that native
process's raw stdout/stderr** (captured when the GUI launches it without UAC elevation shell-out) —
explicitly not the forensic JSONL evidence log, and not written to disk.

---

# PART 2 — Per-Endpoint Features and Logic

## 2.1 Port (USB) — `PORT ENDPOINT\src_usb\`

**What it monitors**: physical USB device arrival/removal (`WM_DEVICECHANGE` via a hidden Win32
message-loop window) and, separately, raw keyboard input timing (`WM_INPUT` via
`RegisterRawInputDevices`) to detect **HID-injection attacks** — a "Rubber Ducky"-style device that
impersonates a keyboard and types malicious commands faster/more mechanically than a human.

**How**: two independent paths converge on identity resolution
(`IsStorageDevice`/`GetMountPointsForDevice` or `IsHidKeyboardDevice`). Storage devices get a
per-device session tracked by `usb_session_manager` with `ReadDirectoryChangesW`-based file-activity
anomaly detection (executable-write, mass-delete, high-volume read/write patterns). HID keyboards
get their raw-input HANDLE resolved by VID/PID and fed to `HidInjectionGuard`, which records up to
32 keystroke timestamps over a 5-second window and evaluates `mean interval < 30ms AND stddev <
15ms` as suspected injection (real humans type with far more timing variance).

**Logic/filtering**: no dedup/compression stage — every device event and every injection verdict is
retained. Retention count (archive rotation) is the only thing `resource_pressure` adjusts.

**Safety guardrails**: none needed — Port is purely observational, takes no action.

**GUI page**: Port/USB — event grid, active-device cards (session-tracked, correctly reconciled on
arrival/removal), a connection notification banner. Right-click row actions: Open Mount Point only
(a USB device has no OS process to Stop/Isolate).

## 2.2 Process — `PROCESS ENDPOINT\titan_fixed\`

**What it monitors**: every process start/lifecycle event system-wide, via the ETW Kernel-Process
provider on a dedicated real-time consumer thread.

**How**: `process_monitor` enriches each event with `OpenProcess`/`QueryFullProcessImageNameW`,
`NtQueryInformationProcess` (command line), and token/SID/integrity queries, plus a bounded
per-PID `ProcessAccumulator` (capped child-name set).

**Logic/filtering — the 7-stage `FilterEngine` pipeline**:
1. `CanonicalisePath`
2. `ClassifyLocation` (is the executable under a known SYSTEM or KNOWN_USER root)
3. `VerifySignature` — `WinVerifyTrust`, run on a background thread with a bounded 250ms wait (a
   real fixed bug: this used to block the ETW thread directly)
4. `ForkThreadSummary`
5. `DllActivity`
6. `PersistenceTouchpoints` — real (not stubbed) checks against HKCU/HKLM Run+RunOnce registry
   targets and the Startup folder
7. `DedupAndCompress` — bloom filters + a ring buffer decide `FORWARD` (write full evidence) vs.
   `COMPRESS` (summarize repeats) — this is the mechanism that can suppress a full record for very
   common, frequently-repeating signed binaries.

**Safety guardrails**: the endpoint itself takes no action — it is pure telemetry. Its
`AsyncLogger` has a hard queue ceiling (`kHardMaxQueue`) that drops-and-counts rather than growing
unbounded under load.

**GUI page**: Process — event grid with parent/child navigation, signer detail, command line, and a
"Related Evidence" cross-endpoint view (PID + time-proximity match against Process/File/Network,
explicitly labeled "Inferred" unless the Correlator itself confirmed the join). Right-click row
actions: Open File Location, Stop Process (re-verifies live identity first), Isolate/Remove
Isolation (real Windows Firewall rule pair).

## 2.3 File Integrity — `FILEEE\`

**What it monitors**: system-wide file create/write/rename/delete via the ETW Kernel-File provider.

**How**: `file_etw_collector` resolves kernel `FileKey`/`FileObject` identities to paths (bounded
cache, 8,192 entries — raised from 1,024 after live testing showed ~38,000 provider callbacks/sec
possible). `file_processor` classifies each file as normal/temp/protected/executable/log-output,
computes SHA-256 for normal files, and maintains a **persistent baseline store** for hash-change
detection. `file_tracker` handles temp-file lifecycle and correlates same-actor-PID/thread activity
within a time window into a `temp_related_activity` record — this was the one correlation precedent
this project had *before* the Correlator existed, and the Correlator's own join logic is a
generalization of exactly this pattern across all 5 endpoints.

**Logic/filtering**: short, uninteresting temp churn (the vast majority of real Windows temp-file
activity) is suppressed by design; temp activity is only promoted to durable evidence if it touches
or becomes an executable target, with full process/PID/TID/old-new-path/reason/identity/time
evidence at that point. A real, previously-confirmed bug (Round 3): `titan_sensors.py`'s own
bookmark-file writes were themselves File events, creating a feedback loop that caused ~48% of
FIM's log volume and measurably dropped ~54,000 real events — fixed by debouncing bookmark saves.

**Safety guardrails**: observational only; no blocking (a real ACL/blocking capability would need a
kernel-mode minifilter driver, explicitly out of scope for this project).

**GUI page**: Files — event grid (Category: Normal/Temporary), a file-hashing tool with DPAPI-backed
baseline storage. Right-click row actions: Open File Location, Stop Process (the process that
touched the file, not the file itself), Isolate/Remove Isolation.

## 2.4 Network — `NETOWRK ENDPOINT\`

**What it monitors**: every raw frame on every eligible network adapter, via the Npcap kernel
driver.

**How**: `network_monitor` opens each adapter (snap length 65,535 bytes, promiscuous mode
requested, one capture thread + one raw-PCAP dumper per adapter), parses
Ethernet/VLAN/ARP/IPv4(+fragmentation)/IPv6(+extension headers)/TCP(flags+state)/UDP/ICMP, and
attributes flows to a local PID/process via `GetExtendedTcpTable`/`GetExtendedUdpTable`.
`protocol_decoder` adds DNS query+response decoding (compression-pointer aware), TLS ClientHello SNI
extraction, and single-packet HTTP request/response-line + Host-header decoding (no stream
reassembly — a disclosed scope limit, not a bug).

**Logic/filtering**: aggregates repeated flow observations rather than logging every packet
individually forever; retains real raw bytes in a bounded 2-slot × 4 MiB per-adapter PCAP ring
(overwrites oldest slot, so disk use is bounded by adapter count, not elapsed time) — genuinely
Wireshark-compatible for deeper external inspection, though the JSONL record and the exact PCAP byte
range are not currently cross-referenced (a disclosed, honest gap — would need a native change to
stamp a `payload_offset`/`pcap_file` field).

**Safety guardrails**: observational only.

**GUI page**: Network — a 3-pane Wireshark-inspired workspace (packet list, protocol-detail tree,
raw capture/bytes pane), display-filter validation/history, protocol hierarchy, top talkers,
conversations, a dedicated Follow TCP Stream window.

## 2.5 Application — `APP\src\`

**What it monitors**: a human-curated watchlist (up to 20 executable identities) of applications —
what they run, open, write, rename, delete, load, and connect to — plus decoded PowerShell/WMI/
Defender/Security Windows Event Log activity system-wide.

**How**: `application_discovery` builds a real desktop catalogue (running processes + HKLM/HKCU
32/64-bit uninstall-registry entries). `applog_watchlist` snapshots active PIDs for selected
identities and follows related child processes (name-agnostic — this is what gives browsers their
multi-process "depth" for free, without special-casing any specific browser). `applog_etw_collector`
+ `applog_event_subscriber` feed a selected-PID-filtered ETW session (Kernel-Process, Kernel-File)
and four Windows Event Log subscriptions (Security 4625/4672/4688, Defender 1116-1118,
PowerShell-Operational 4104, WMI-Activity 5859/5861). `applog_decoder` decodes that XML into
structured JSON with 52 detection patterns. `CollectNetworkBehavior()` separately polls
`GetExtendedTcpTable`/`UdpTable` for every currently-watched PID every ~2s cycle, emitting real
`protocol`/`local_endpoint`/`remote_endpoint`/`connection_state` per socket (this is the data the
GUI's Applications page now surfaces — it existed natively long before the GUI displayed it).

**Logic/filtering**: watchlist changes are synced live from `config\watchlist.txt` (polled every
~2s) rather than only at startup, with a written acknowledgement (`watchlist_state.json`) so the GUI
can show a real applied/pending indicator instead of assuming its own write took effect.

**Safety guardrails**: no launch capability at all — selecting an application to watch never starts
or restarts it; only already-running matching processes are observed.

**GUI page**: Applications — a Catalog tab (discovered/installed/running, with live watchlist add/
remove) and an Activity tab (event grid including the network-socket fields above, an "Observed
Applications" summary with a real currently-running indicator and cross-referenced bytes sent/
received pulled from the Network endpoint's own tailer by PID). Right-click row actions: Open File
Location, Stop Process, Isolate/Remove Isolation.

## 2.6 Correlator — `CORRELATOR\`

**What it does**: the only one of the 6 native programs that *reads* the other 5's output — never
writes into any of them, needs no elevation.

**How**: `main.cpp` loads `correlator_config.txt` (superseded in practice by
`runtime-manifest.json`'s authoritative log directories), builds one `LogTailer` per source
endpoint, and runs a ~3-second poll loop. Each tailer tracks its own per-file byte offset, reads
only newly-appended bytes, handles partial trailing lines, auto-picks-up rotated files by
filename-hint match, and drops tracking for files that vanish (never treated as an error — that's
the source endpoint's own retention pruning). `correlation_engine` maintains a bounded evidence ring
per endpoint (2,000 entries or 60 seconds old, whichever prunes first) and runs a two-pointer
time-ordered scan **per endpoint pair** (not a full cross-product) to find candidate joins.

**Join predicate** (`RecordsCorrelate`, within a configurable window, default ±2000ms): same PID,
OR one record's PID equals the other's parent PID (either direction), OR both share the same
nonzero parent PID (siblings) — plus a Port-specific time-proximity-only predicate, since Port
carries no OS PID at all.

**Logic**: a matched pair emits or extends a `session_timeline` group (up to 8 members, up to 500
concurrent groups), marking both records consumed so they're never re-joined on a later cycle. Each
member carries a real, scored confidence (`ScoreConfidence` — base weight per join reason, decayed
by how much of the join window the actual time delta used) and, when the source endpoint has
stamped one, the exact durable reference back to its original record (see Part 1 §1.6).

**Known, disclosed limitation**: live cross-endpoint correlation with real multi-endpoint members
was not reliably observed in fully-automated test harness runs (Round 3's own finding) — the
underlying graph logic is proven correct by deterministic unit tests and this session's own
byte-offset verification, but automated synthetic child processes didn't reliably get picked up by
Network/File the way they were by Process, likely due to each endpoint's own by-design dedup/
coalescing/snapshot-attribution behavior. Santosh testing interactively at his own keyboard remains
the recommended way to observe this live.

**Safety guardrails**: none needed — read-only, no action capability.

**GUI page**: Correlation — master-detail group list + per-group delta-ms timeline, an evidence
graph with confidence-weighted edges, a genuine source-coverage-gap indicator (diffs a group's
participating endpoints against the 5 known categories), and per-member "Evidence" buttons that
resolve the exact original byte range via `EvidenceResolver` (verified this session against real
data).

## 2.7 CUSTOM RULE — `CUSTOM RULE\`

**What it does**: lets a human describe a detection/response rule, validates and simulates it,
and — once approved — actually watches for it live and can respond.

**Rule authoring pipeline** (identical for both entry points below): Input Length Gate (4,000-char
default) → Injection Screener (HIGH-confidence patterns block before the LLM is ever called;
LOW-confidence patterns pass through with warning flags) → Context Builder (OS, collectors, fields,
operators, actions, and the current user's permissions) → for English only, Prompt Builder + Groq
API call (temperature 0, max 3 calls, retry → fallback model → terminal failure) → JSON Extractor →
Semantic Validator (Pydantic structural + contextual/capability checking against the deployment
context) → Simulation against retained evidence.

- **English path** (`/api/parse-rule`): the LLM is called exactly once per rule, only at authoring
  time — never in the runtime detection path, never given access to live telemetry.
- **YAML path** (`/api/rules/from-yaml`, `app\yaml_rules.py`): bypasses the LLM entirely, for when
  Groq is at quota or for offline/scripted authoring. Runs through the **exact same** structural/
  contextual/capability/simulation pipeline as an LLM draft — same response shape, same review UI,
  same `/api/rules/approve` call. Required fields: `trigger_event`, `severity`, `priority` (severity
  deliberately has no silent default — it's safety-relevant).

**Approval** (`/api/rules/approve`): re-validates the human-selected response actions against the
`ActionType` enum (empty list rejected), re-runs capability checking with those actions actually
injected into the IR (the only point where real actions exist to check permissions against), then
persists to `rules.jsonl`. Duplicate semantically-identical rules are detected and return
`already_approved` with the existing rule's ID rather than creating a second copy.

**Rule types supported**: single-condition, `aggregation` (fires only once a threshold count of
matching events occurs within a time window — verified live this session: correctly withheld firing
after 1 of 2 required occurrences, fired after the 2nd), `correlation` (multi-stage, e.g. "process A
AND process B within 1 minute" — verified live this session with two real triggered processes), and
`sustain_for` (fires only if the triggering condition remains true for a minimum duration — e.g. "a
process that stays running for 2+ seconds," verified in an earlier round with exact duration
timing).

**Runtime watcher** (`watcher\main.py`): polls ~10 collectors (system, WMI, registry FIM, inventory,
Sysmon, PowerShell, scheduled tasks, USB, firewall, Defender) plus `titan_sensors.py` (the bridge
into the 5 native TITAN sensors' JSONL logs + the Correlator's own `session_timeline` output — reuses
existing event vocabulary like `process.start`/`file.create`/`dns.query`/`network.connect` where
semantics match, and adds `titan.*`-namespaced types for TITAN-only signals like USB HID-injection
alerts). Every observed event is checked against every currently-loaded rule; **a match is the only
thing that ever produces a persisted alert or evidence record** — unmatched telemetry is
transient-only by explicit storage policy.

**Response actions and their real guardrails** (`watcher\action_engine.py`):
- `alert` — always safe, just writes the alert + evidence record.
- `kill_process` — re-verifies the live process's name/creation-time immediately before acting
  (protects against PID reuse since the rule matched), refuses to touch any of TITAN's own 6 native
  components or core OS processes, rate-limited by a 5-per-minute circuit breaker.
- `isolate_host` — layered guardrails: refuses an unverifiable target host; refuses self-isolation
  entirely unless `WATCHER_ALLOW_SELF_ISOLATE=true` is explicitly set (this is a single-host
  deployment — the only real enforcement mechanism is a local Windows Firewall rule on the machine
  the watcher itself runs on, so by default it can never isolate that machine); refuses while an
  active RDP/SSH/WinRM management session is established (a block-all-outbound rule can't safely
  carve out an exception for the operator's own session); same circuit-breaker rate limit as kill.

**GUI integration**: 5 tabs on the Custom Rules page — Rule Authoring (the Describe → Review
Structure → Test → Approve wizard), Watcher Coverage (live capability map — which collectors/event
types are actually active right now, verified this session to show real data), Approved Rules
(search/promote-to-knowledge/delete), Watcher Activity (live bounded diagnostic feed), and Matched
Evidence & Outcomes (a redirect notice — this workflow is deliberately unified onto the Alerts &
Evidence page rather than duplicated as a second table).
