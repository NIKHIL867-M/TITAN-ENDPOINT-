# TITAN Cross-Endpoint Correlation — Design Analysis

Analysis completed: 30 July 2026 local time
Scope: design and evidence only — no correlator implementation in this pass
Grounded in: direct source reading of all 5 endpoints' current code, not prior reports

## 1. The problem, stated precisely

TITAN ENDPOINT is 5 independent native C++20 Windows programs — Application
(`APP`), File Integrity (`FILEEE`), Network (`NETOWRK ENDPOINT`), Port/USB
(`PORT ENDPOINT`), Process (`PROCESS ENDPOINT`). Each has its own `CMakeLists.txt`,
its own process, its own JSONL (or timestamped-JSON) log output, and zero
shared code, headers, or log-directory convention. Confirmed by reading every
module's build file and entry point:

- No `add_subdirectory`, no shared library, no common header between any two
  endpoints.
- No correlation ID, session ID, or logon ID exists anywhere in any of the 5
  codebases (checked every `event.h` / `_file_scope.h` / equivalent schema
  header).
- Each endpoint runs as its own executable with its own main loop
  (`agent.cpp`, `main.cpp`, `main_test.cpp`, `test_main.cpp`) and writes to a
  log directory it alone controls.

Because there is no shared process, no shared memory, and no IPC channel
between the 5 agents, **correlation cannot happen inside any one endpoint's
process**. It has to happen at the evidence layer — after the fact, over the
logs each endpoint already produces — or not at all in the current
architecture.

Three concrete obstacles stand in the way of joining these logs today, found
by direct inspection:

### 1.1 Inconsistent timestamp precision

| Endpoint | Field | Precision | Source |
|---|---|---|---|
| Port (USB) | `timestamp` | millisecond (`GetCurrentTimeISO`, ms via `%3d` fraction) | `usb_session.cpp` (`GetCurrentTimeISO`), mirrored in the new `usb_monitor.cpp` health/HID records |
| Process | `log_time` / `ts` | microsecond (`FormatTimestamp`, 6-digit fraction) | `event.cpp:97-116` |
| File Integrity | `timestamp` | **whole seconds only** — no fractional part | `file_processor.cpp:818-822` (`"%Y-%m-%dT%H:%M:%SZ"`) |
| Network | `capture_epoch_us` (separate int field) + a formatted string | microsecond, but as a **separate integer field**, not baked into the timestamp string | `event.cpp:147` (`NETOWRK ENDPOINT`) |
| Application | `timestamp` | millisecond (Windows Event Log `TimeCreated`, passed through as-is) | `applog_decoder.cpp:439` |

A correlator that buckets events by time has to special-case every one of
these five representations before it can even bucket-join two records. File
Integrity's whole-second precision is the tightest constraint: two file
events genuinely 900ms apart are indistinguishable from simultaneous in its
log today.

### 1.2 Inconsistent field naming for the same concept

The same real-world concept has a different JSON key in each endpoint:

- File Integrity emits the executing process as `"process"` (`file_processor.cpp:833`).
- Process emits it as `"process_name"` (`event.cpp:382-384`).
- Application emits it under `"source"` / embeds it in decoded event text,
  not as a normalized process field at all (`applog_decoder.cpp:437`).
- Network's schema (not read in this pass in full detail) uses its own
  process-attribution field, separately named again.

A correlator has to carry a per-endpoint field-name map rather than reading
one canonical key.

### 1.3 A confirmed, real bug: Application drops pid/tid it already has

`APP\src\applog_decoder.cpp`'s `BuildJson()` (lines 432-452) emits
`source`, `event_id`, `timestamp`, `summary`, `script_content`,
`script_path`, `encoded_decoded`, `network_activity`, and four boolean
detection flags — but never `pid` or `tid`. Checking `DecodedEvent`
(`applog_decoder.h`), the struct itself has no `pid`/`tid` fields either, so
this isn't a one-line oversight in `BuildJson()` — the decode pipeline drops
process identity before it ever reaches the struct that becomes JSON, even
though the underlying ETW/Windows-Event-Log source event carries a PID (every
Windows Event Log record has an originating process ID). This means
`application_log` records — the one record type most likely to carry
PowerShell/WMI/Defender/Security detection signal — cannot be joined to a
Process-endpoint PID today at all. This is a real, fixable gap, not a design
limitation.

## 2. Minimal, additive, non-breaking schema normalization

None of the changes below remove or rename an existing field. Every existing
consumer of current JSON keeps working unmodified; a correlator (or any
future consumer) gets new fields to key on.

1. **`t_unix_ms` (int64, UTC epoch milliseconds) on every record, every
   endpoint.** Computed once, alongside each module's existing
   human-readable timestamp, at the exact point that timestamp is already
   being formatted (e.g. right next to `file_processor.cpp:818`'s
   `to_time_t` call, `event.cpp:97`'s `FormatTimestamp`, etc.). This gives
   every endpoint one shared, precision-normalized numeric join key without
   touching any existing string timestamp field.

2. **Consistent `pid` / `tid` / `parent_pid` presence, same field names,
   across all 5 endpoints** — present with value `0` (or absent) when not
   derivable, never silently omitted when it *is* derivable. Concretely:
   - Fix `APP\src\applog_decoder.h` / `applog_decoder.cpp` to carry `pid`
     and `tid` from the source Windows Event Log record into `DecodedEvent`
     and then into `BuildJson()`'s output (Section 1.3). This is the one
     genuine bug in this list; everything else here is normalization, not a
     fix.
   - Standardize on `pid` / `parent_pid` / `tid` as the field names
     everywhere (File Integrity, Process, and Port already use `pid`/`tid`
     internally in some form; Application needs the addition above; Network
     needs its existing process-attribution field re-keyed to match, additively
     — keep the old key alongside the new one if anything external already
     reads it).

3. **A single canonical `process` identity field** (executable name or full
   path — pick one, but the same one everywhere) alongside whatever
   endpoint-specific name each module already uses (`process`,
   `process_name`, etc.) — additive alias, not a rename, so nothing breaks.

None of this requires touching ETW providers, adding IPC, or synchronizing
clocks beyond what `std::chrono::system_clock` already gives each process
(all 5 endpoints run on the same host, so wall-clock skew between them is
zero by construction — this is a formatting-consistency problem, not a
distributed-clock problem).

## 3. Recommended correlation architecture

Real-time, in-process correlation is not available without a materially
larger redesign (shared IPC bus, a common event schema all 5 endpoints
speak, or merging the 5 executables into one process — none of which are in
scope here and none of which the existing architecture was built for). The
File endpoint's own final report is explicit that its endpoint owns file
evidence only and does not compile or launch the other endpoints; the same
boundary exists, deliberately, on all 5 sides.

Given that, the workable design is a **lightweight, standalone Correlator**
— a 6th, read-only process that:

1. **Tails all 5 endpoints' JSONL/JSON logs**, including rotated/archived
   files (every endpoint now has, or already had, a bounded-retention
   rotation scheme: File's `file_logger.cpp` retention cap, Process's newly
   added `AsyncLogger::PruneOldPacks` — this session — Port's newly added
   `UsbLogger::PruneOldArchives` — this session — and Network/App's existing
   schemes). The Correlator needs to know each endpoint's log-directory
   convention and rotation naming pattern to avoid missing evidence that
   rotated out from under it mid-tail.
2. **Joins records** on `t_unix_ms` (bucketed — e.g. a configurable ±N-second
   window, wide enough to absorb File Integrity's whole-second precision
   floor from Section 1.1) **and** `pid` (with a parent-PID lineage walk
   for cases where the same logical activity shows up under a child PID in
   one endpoint's view and the parent's PID in another's — Process already
   tracks `real_parent_pid` for exactly this kind of lineage reasoning,
   `event.h:176`).
3. **Emits a joined "session timeline"** — a new, separate JSONL output that
   is additive evidence, not a replacement for any endpoint's own log.

This generalizes the one proven correlation precedent that already exists in
the codebase today: File Integrity's `temp_related_activity` correlation
(`file_tracker.cpp:555-572`). That code already does, within one endpoint,
exactly the join a cross-endpoint Correlator needs to do across five:

- it matches on **actor identity** — `same_actor_pid` when only the PID
  lines up, `same_actor_thread` when the more specific TID lines up too
  (`file_tracker.cpp:559-561`, `567`);
- it matches within a **bounded time window** (`origin.born_at` age check,
  `file_tracker.cpp:557-558`);
- it emits the join as its **own record type** (`"type":"temp_related_activity"`,
  `file_tracker.cpp:564`) alongside — not instead of — the original file
  event, exactly the "additive evidence" shape recommended for the
  Correlator's output.

The Correlator is the same idea, widened from "one endpoint's own event
history" to "5 endpoints' independent logs," using the `t_unix_ms` +
`pid`/`parent_pid` fields from Section 2 as the join keys File Integrity
already had natively available to it in one process.

## 4. Explicit non-goals for this pass

The following are Santosh's own stated next-round items and were not started,
touched, or designed against in this pass:

- Building the actual Correlator engine (Section 3 is a design, not code).
- RAM/disk "auto-lightening" adaptive throttling.
- "Condition search."
- RAG.

## 5. What this pass actually changed toward this goal

Nothing in Sections 2-3 above has been implemented yet — this document is
the analysis and design only, per the agreed scope for this pass. The
concrete, already-shipped groundwork this session laid that a future
Correlator will depend on:

- Both Port and Process gained real, evidence-emitting `collector_health`
  records (`usb_monitor.cpp::EmitHealthRecord`, `process_monitor.cpp::EmitHealthRecord`)
  matching the `collector_health` shape File and Network already had —
  meaning all 5 endpoints now have a consistent health/loss-evidence record
  type for a future Correlator to key on for "was this endpoint's evidence
  complete during this time window" reasoning.
- Both Port and Process gained bounded log/artifact retention
  (`UsbLogger::PruneOldArchives`, `AsyncLogger::PruneOldPacks`) — a
  Correlator tailing rotated files needs bounded, enumerable rotation
  archives to reason about, not unbounded accumulation.
