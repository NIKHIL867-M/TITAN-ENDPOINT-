# TITAN Endpoint — Application Walkthrough

> **A page-by-page guide to what the application shows and why it matters**  
> *Prepared for presentation — based on live, freshly-started runs with real activity (nothing shown is mocked or staged data).*  
> 📄 **Download Original Presentation Slides**: **[`docs/TITAN_Endpoint_Application_Walkthrough.pdf`](./docs/TITAN_Endpoint_Application_Walkthrough.pdf)**

---

## Executive Summary

**TITAN Endpoint** is a modular, cross-endpoint security monitoring platform:
- **Five independent native collectors** (Process, Network, Applications, Files, Port/USB) tap directly into **Kernel ETW**, **Windows Event Logs**, **Npcap wire capture**, **Kernel device listeners**, and **Filesystem changes** to write tamper-evident evidence logs.
- A **Correlator** ties related evidence across those collectors into real-time incidents.
- A set of **extensible consumer layers and addons** on top:
  - **Custom Rule Engine**: Guided natural language ("Write in English") & YAML behavioral rule engine.
  - **Alerts & Evidence Log**: Cryptographically HMAC-verified alerts with dry-run support.
  - **OpenCTI Addon**: Real-time STIX 2.1 Bundle exporter for enterprise threat-intelligence platforms.
  - **Own AI Model for Behavior Analysis**: AI-driven behavioral analysis and dynamic rule translation.

It is deliberately built as a **monitoring substrate** rather than a standalone antivirus replacement: the goal is rich, trustworthy visibility that other systems (Defender, a SOC, an AI analyst) can attach to, not a closed detection product.

---

## 1. Overview

### What This Is
The command centre. It's the first page TITAN opens on, and it summarizes every endpoint's state in one place rather than making you check five separate pages.

### What the Output Shows
- An **overall fleet state** (`Active` / `Degraded` / `Stopped`).
- A **5-card status row** — one per endpoint — each with its own Logging on/off toggle, last heartbeat age, and live events/sec.
- **Session totals** (events this session, alerts by severity, TITAN's own RAM use, dropped events).
- A live **Recent Activity feed** with a per-row Evidence button.
- A **Resource Usage panel** tracking TITAN's own memory and disk footprint over time.

### What It Indicates
- A green dot and recent heartbeat means that collector is alive and current.
- A **Degraded** badge means the collector itself reported a problem or its heartbeat is stale — worth checking before trusting data from that specific endpoint.
- **Dropped Events staying at 0** means nothing is being silently lost under load.

### Use Case
The single screen to glance at before trusting anything else in the app, and the fastest way to show an audience: *"yes, this is actually running and watching the machine right now."*

---

## 2. Process

### What This Is
The Process endpoint's live view — every process start/stop and periodic snapshot on the machine, with a detail pane underneath for whatever row is selected.

### What the Output Shows
- A table of `Time` / `Action` / `Process` / `PID` / `PPID` / `User` / `Integrity` / `Elevation` / `Signer` / `Command Line`.
- Inspection tabs below (`Command Line`, `Signer`, `Parent/Children`, `Related Evidence`, `Raw Record`) for deep inspection of one selected process.

### What It Indicates
- The **Signer** column is the one to watch — **"Unsigned / unverified"** next to a process running as `NT AUTHORITY\SYSTEM` or under an elevated context is exactly the kind of row a real investigation starts from.
- **Parent/Children** lets you trace whether a process was spawned by something expected (e.g. `explorer.exe`) or something suspicious.

### Use Case
Core EDR-style visibility: catching unauthorized or unusual process launches, privilege escalation, and unsigned tooling — the same category of signal commercial EDR products lead with.

---

## 3. Network

### What This Is
The Network endpoint's live view — real packet capture via Npcap, decoded and attributed to the process that owns each connection.

### What the Output Shows
- A **live capture stat bar** (packets captured/dropped, source loss, rate).
- A **flow table** (`Process` / `Local` / `Remote` / `Protocol` / `Direction` / `State` / `bytes sent-received`).
- A **Protocol Hierarchy panel** breaking traffic down by protocol (`HTTPS_TLS`, `DNS`, `ICMP`, `QUIC`, etc.).
- When a row is selected: a **Protocol Details tree** plus a link to the exact raw packet bytes.

### What It Indicates
- Which process is talking to which address, over what protocol, and whether that traffic actually matches what its own port implies.
- A connection flagged **"Expected protocol: HTTPS_TLS / Protocol mismatch: Yes"** in the detail pane means something is running non-TLS traffic over port 443 — a real evasion technique, not a false alarm.

### Use Case
Full network visibility with real process attribution, plus a **protocol/port-mismatch detector** that catches traffic dressed up as something it isn't — the same class of technique malware uses to blend in with normal HTTPS traffic on a firewall-friendly port.

---

## 4. Applications

### What This Is
The Applications endpoint's live view — application-layer activity (installs, file and network actions tied to a named application) tracked separately from the lower-level Process/Network/File endpoints.

### What the Output Shows
- A live feed of **application-attributed events**.
- A **monitored-application watchlist** that can be explicitly added to or removed from — scoping which applications get this extra layer of attention.

### What It Indicates
Activity here is application-attributed rather than raw-process-attributed, so it answers *"what did this specific application do"* even when that maps to several underlying processes.

### Use Case
Tracking the behavior of specific applications of interest (e.g. a browser, an office suite, a custom tool) as a named unit, rather than having to reconstruct that story by hand from Process and Network rows.

---

## 5. Files

### What This Is
The File Integrity Monitoring (FIM) endpoint's live view — tracks create/write/delete activity and content hashes for files under watch (by default the user's Desktop, Documents, and other sensitive paths).

### What the Output Shows
A live feed of file events with the path, the action (create/write/delete), and the file's hash at that point in time.

### What It Indicates
A hash that changes between two events on the same path means the file's actual content changed — confirmed with real live testing (create a file, confirm its hash, modify it, confirm the hash changed).

### Use Case
**Tamper detection**: catching unauthorized modification of sensitive files — configuration tampering, ransomware touching user documents, malware planting itself in a startup path.

---

## 6. Port / USB

### What This Is
The Port/USB endpoint's live view — tracks removable media and other peripheral device insertion/removal.

### What the Output Shows
A live feed of device connect/disconnect events, distinguishing storage devices (USB drives) from non-storage peripherals.

### What It Indicates
An unexpected storage device appearing on a machine that shouldn't have one plugged in is the classic signal this page exists to catch. Furthermore, it tracks HID input timing to detect automated keystroke injection (Rubber Ducky / BadUSB attacks).

### Use Case
Data-exfiltration awareness and physical asset control — knowing when removable media touches a monitored machine, not just what happens over the network.

---

## 7. Correlation Graph

### What This Is
A live node-graph visualization of the Correlator's own work: which endpoints are currently being tied together by shared evidence, and how strongly.

### What the Output Shows
- One node per endpoint (with its live record count).
- Edges between nodes that the Correlator has actually joined evidence across.
- A numeric badge per edge showing how many connections back that association.
- A **Per-Endpoint Summary table** (`Status` / `Records Seen` / `Cross-Links` / `Last Seen`).

### What It Indicates
An edge is an observed association, not a claimed direction or cause — it means the Correlator found evidence from both endpoints that belongs to the same real-world activity (e.g. the same PID). A thicker/brighter edge means more shared evidence has accumulated between that pair.

### Use Case
The fastest visual answer to *"is anything actually being correlated right now, and between which parts of the system"* — useful both for monitoring and for spotting an endpoint that's gone quiet (no edges forming).

---

## 8. Incident Graph

### What This Is
The full-page list of every real correlated incident the Correlator has produced, each shown as one expandable card rather than a graph node.

### What the Output Shows
- Per incident: the endpoints it touched, in order (e.g. `Process → Network`).
- What's common across every member of the incident (process name, PID, time span).
- One small card per endpoint segment with its own Evidence button linking back to the raw record.

### What It Indicates
This is the connected story a human actually reads: e.g. one process that both wrote a file and opened a network connection within the same short window — a shared PID linking Process, File, and Network evidence into a single real incident instead of three unrelated log lines.

### Use Case
**Incident triage**: this is the page an analyst opens to understand *"what happened"* as a narrative, not a table. **Pause Live Updates** freezes the list so a specific card can be read or clicked before it scrolls away.

---

## 9. STIX Export

### What This Is
Converts the Correlator's own correlated incidents into a **STIX 2.1 Bundle** — the standard format OpenCTI and most other threat-intelligence platforms expect — plus a Send & Receive feature to hand the resulting file to another machine.

### What the Output Shows
- The live source file being read (`correlated_events.json`, with its size and last-write time).
- A **Convert to STIX** button and the last conversion result.
- A **Send & Receive panel** with a shared token and reachable address for pushing the bundle to another machine running OpenCTI.

### What It Indicates
Only **"observed-data"** STIX objects are written — never "indicator" objects. TITAN records what it actually saw (a real IP, a real file hash, a real process); judging whether that's malicious is deliberately left to OpenCTI or whoever consumes the export.

### Use Case
This is what turns TITAN from a standalone viewer into a feed for a real SOC pipeline: any platform that speaks STIX 2.1 can ingest TITAN's evidence directly, which is the concrete version of *"TITAN is meant to be attached to other systems"* rather than replace them.

---

## 10. Custom Rules

### What This Is
A guided rule-authoring wizard (`Describe → Review Structure → Test → Approve`) for defining detection rules against live activity, without writing code.

### What the Output Shows
- Watcher status (rules loaded, dry-run state).
- Two authoring paths:
  1. **"Write in English"** (parsed by a local LLM-assisted service into a structured rule).
  2. **"Write / Import YAML"** directly.
- Tabs for **Watcher Coverage**, **Approved Rules**, **Watcher Activity**, and **Matched Evidence & Outcomes**.

### What It Indicates
A rule described in plain English (e.g. *"Alert when powershell.exe spawns a network connection to a non-standard port within 30 seconds of a Word document opening"*) gets turned into a real structured rule the Watcher can evaluate against live events — nothing is executed directly from the description text.

### Use Case
Lets a non-programmer describe detection logic in their own words instead of learning a rule syntax — the same detection engine, but with the authoring barrier removed.

---

## 11. Alerts & Evidence

### What This Is
The output side of the Custom Rule Watcher — every time a live event matches an approved rule, it lands here as an alert with its supporting evidence.

### What the Output Shows
- Watcher status and response mode (`Dry Run` on/off).
- Session alert totals by severity (low / medium / high).
- A table of `Time` / `Severity` / `Event` / `Rule` / `Rule ID` / `Mode` / `Action Results` / `Evidence Integrity` / `Ack` — e.g. *"Alert if PowerShell is started"* firing on real `powershell.exe` launches.

### What It Indicates
- Evidence Integrity shows **"Verified by backend HMAC check"** — each alert's supporting evidence is cryptographically tied to the record it was raised from, so it can't be silently altered after the fact.
- **Dry Run ON** means matched actions are recorded but not actually executed.

### Use Case
The place to answer *"did anything actually get flagged, and can I trust that flag"* — tamper-evident alerting on top of the raw telemetry the other pages show.

---

## 12. Unified Logs

### What This Is
One searchable stream merging every endpoint's raw event log in a single place, instead of checking five separate pages one at a time.

### What the Output Shows
The full raw JSON record for every event across Process, Network, Applications, Files, and Port/USB, filterable and searchable in one view.

### What It Indicates
This is the ground truth — every field any other page summarizes or visualizes ultimately comes from a raw record visible here, unabridged.

### Use Case
Free-text investigation across the whole machine at once (e.g. *"show me everything that mentions this IP"* or *"everything from this PID"*), and the fastest way to confirm a new field or event actually reached the log during development.

---

## 13. System Health

### What This Is
An operational health monitor for TITAN's own pipeline — not the endpoint data itself, but whether the collectors, Correlator, and Custom Rule components are running correctly.

### What the Output Shows
- A fleet-wide **events/sec sparkline**.
- One row per component with `State` (`Healthy` / `Degraded` / `Stale` / `Stopped`), last heartbeat, session/PID, records `Seen vs. Written`, `queue depth`, `Lost/Failed` count, `disk retained`, `restart count`, and `resource pressure`.

### What It Indicates
- **Lost/Failed staying near zero** and **Seen ≈ Written** means the pipeline isn't silently dropping data under load.
- A **Degraded** or **Stale** state on a specific component pinpoints exactly which one needs attention rather than a vague *"something's wrong."*

### Use Case
Pre-flight and ongoing operational confidence — the page to check before trusting a demo or a real deployment, and the first place to look if a page elsewhere seems to be missing data.

---

## 14. Settings

### What This Is
Configuration for endpoint executable/log paths, the Custom Rule service, disk retention budgets, and interface preferences.

### What the Output Shows
- Per-endpoint runtime manifest path, log directory, and log file pattern (manifest-owned fields shown read-only).
- Custom Rule data directory and local API URL.
- Global disk budget and minimum free-space reserve in GB.
- **Reduced Motion** and **Compact Table Density** toggles.

### What It Indicates
Paths marked as coming from the **"Runtime manifest (authoritative)"** are generated automatically after each native rebuild and are intentionally not hand-editable here, to prevent the GUI and the actual built executables from drifting out of sync.

### Use Case
Where disk usage is kept bounded (so TITAN doesn't fill the disk with its own logs) and where the interface can be tuned for a specific machine or presentation (e.g. Reduced Motion for a low-power projector setup).

---

## How It Fits Together

```
   [ Process ]     [ Network ]     [ Applications ]     [ Files ]     [ Port/USB ]
        │               │                 │                 │              │
        └───────────────┴────────┬────────┴─────────────────┴──────────────┘
                                 │
                     [ Correlator Engine ]
                                 │
             ┌───────────────────┼───────────────────┐
             ▼                   ▼                   ▼
    Correlation Graph      Incident Graph       STIX 2.1 Export
    (Live associations)  (Readable narrative)   (OpenCTI / SOC)
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
       Custom Rules                         Unified Logs & Health
  (English / YAML & HMAC Alerts)            (Ground truth & Diagnostics)
```

**Process**, **Network**, **Applications**, **Files**, and **Port/USB** each run as independent native collectors, writing their own evidence log regardless of whether anything else is running.

1. The **Correlator** reads all five logs and joins evidence that belongs to the same real activity into incidents, visualized on the **Correlation Graph** (the live association map) and **Incident Graph** (the readable per-incident story).
2. On top of that, three optional consumer layers each do one job:
   - **Custom Rules + Alerts & Evidence**: turn matching activity into tamper-evident alerts cryptographically verified via HMAC.
   - **STIX Export**: turns correlated incidents into a standard format any real threat-intelligence platform (like OpenCTI) can ingest.
   - **Unified Logs + System Health**: give raw, unabridged access to ground truth for deep forensic investigation and operational verification.
