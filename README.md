# TITAN ENDPOINT — Unified Endpoint Detection & Response (EDR) Suite

[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-blue.svg)](https://microsoft.com)
[![Framework: .NET 8 WPF](https://img.shields.io/badge/GUI-.NET%208%20WPF-purple.svg)](https://dotnet.microsoft.com/)
[![Native: C++20](https://img.shields.io/badge/Core-C%2B%2B20%20%2F%20CMake-00599C.svg)](https://isocpp.org/)
[![Python: 3.12](https://img.shields.io/badge/Rules-Python%203.12%20FastAPI-green.svg)](https://fastapi.tiangolo.com/)

**TITAN ENDPOINT** is an enterprise-grade, multi-sensor Endpoint Detection and Response (EDR) platform designed for Windows. It couples a hardened native C++ telemetry collector fleet with real-time cross-sensor event correlation, custom behavioral detection rules, and an interactive .NET 8 WPF security operator dashboard.

---

## 🏛 Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                        TITAN Operator Dashboard (WPF GUI)                         |
|   Fleet Controller | Incident Graph | Packet Viewer | STIX Exporter | Diagnostics |
+-----------------------------------------+-----------------------------------------+
                                          | Named Pipes IPC
+-----------------------------------------+-----------------------------------------+
|                              Correlator Engine                                    |
|             Cross-Sensor Incident Graph & Session Timeline Reconstruction         |
+---------+--------------------+--------------------+--------------------+----------+
          |                    |                    |                    |
+---------v----------+ +-------v----------+ +-------v----------+ +-------v----------+ +---v--------------+
|  Process Endpoint  | | Network Endpoint | |   Application    | |  File Endpoint   | |    Port / USB    |
|  (titan_process)   | |   (titan.exe)    | |    (app_log)     | |   (file_test)    | |    (usb_test)    |
+--------------------+ +------------------+ +------------------+ +------------------+ +------------------+
|  Kernel ETW        | |  Npcap Wire      | |  Windows Event   | |  Kernel FIM /    | |  Kernel PnP /    |
|  Kernel-Process    | |  Driver & OS     | |  Logs (PS, WMI,  | |  Directory       | |  Storage Auditor |
|  & Win32 API       | |  Socket Map      | |  Defender) & ETW | |  Changes & SHA256| |  & HID Timing    |
+--------------------+ +------------------+ +------------------+ +------------------+ +------------------+
                                          |
                              +-----------v------------+
                              |  Custom Rule Service   |
                              | (FastAPI / Behavioral) |
                              +-----------+------------+
                                          |
          +-------------------------------+-------------------------------+
          |                                                               |
+---------v-----------------------------------+ +-------------------------v-------------------+
|             OpenCTI Addon                   | |      Own AI Model for Behavior Analysis     |
| (STIX 2.1 Threat Intel Platform Integration)| |  (AI Behavioral Engine & Natural Language)  |
+---------------------------------------------+ +---------------------------------------------+
```

### 🔌 External Integrations & Addons
- **OpenCTI Addon**: Converts multi-source correlated incidents into standardized **STIX 2.1 Bundles** (`observed-data`) and enables real-time peer export to OpenCTI / SIEM platforms.
- **Own AI Model for Behavior Analysis**: Embedded AI-assisted intelligence providing:
  - **Natural-Language Rule Authoring**: Transforms plain-English analyst intent (e.g. *"Alert when powershell.exe connects to external IP within 30s of Word opening"*) into structured behavioral detection rules.
  - **Behavioral Anomaly Analysis**: Analyzes multi-sensor timelines to detect novel multi-stage attack chains and evasion patterns.

---

## 🖥 Application Walkthrough & Operator Guide

> 📖 **Full presentation guide available in [`APPLICATION_WALKTHROUGH.md`](./APPLICATION_WALKTHROUGH.md)**  
> 📄 **Download Original Presentation Slides**: **[`docs/TITAN_Endpoint_Application_Walkthrough.pdf`](./docs/TITAN_Endpoint_Application_Walkthrough.pdf)** (16 pages of live UI captures with real machine activity).

TITAN Endpoint provides a unified operator console across 14 dedicated security views:

| # | Page / Module | Role | Key Signals & Output | Primary Use Case |
|---|---|---|---|---|
| **1** | [**Overview**](./APPLICATION_WALKTHROUGH.md#1-overview) | Fleet Command Centre | 5-card status row, live events/sec, session totals, resource footprint | Instant single-pane fleet status verification |
| **2** | [**Process**](./APPLICATION_WALKTHROUGH.md#2-process) | Kernel ETW Process Telemetry | PID/PPID tree, 7-stage filter, digital signatures, user context | Detect unauthorized binaries & privilege escalation |
| **3** | [**Network**](./APPLICATION_WALKTHROUGH.md#3-network) | Wire-Level Packet Attribution | Npcap live capture, DNS/TLS SNI decoders, protocol/port mismatch | Catch malware blending into standard ports (e.g. 443) |
| **4** | [**Applications**](./APPLICATION_WALKTHROUGH.md#4-applications) | Application-Level Auditing | Monitored-app watchlist, script-block logs (PowerShell/WMI) | Audit high-value apps and detect AMSI bypass |
| **5** | [**Files**](./APPLICATION_WALKTHROUGH.md#5-files) | File Integrity Monitoring (FIM) | Real-time create/write/delete, SHA-256 baseline, temp promotion | Tamper detection, ransomware defense, startup persistence |
| **6** | [**Port / USB**](./APPLICATION_WALKTHROUGH.md#6-port--usb) | Peripheral & HID Injection Guard | Device connect/disconnect, storage sessions, keystroke timing | Stop BadUSB / automated HID keystroke injection |
| **7** | [**Correlation Graph**](./APPLICATION_WALKTHROUGH.md#7-correlation-graph) | Live Association Map | Live node graph, edge connection strength, cross-links count | Visualize cross-sensor activity & spot quiet endpoints |
| **8** | [**Incident Graph**](./APPLICATION_WALKTHROUGH.md#8-incident-graph) | Narrative Incident Triage | Timeline story cards, ordered attack stages (Process → Network) | Understand complex attacks as a human-readable story |
| **9** | [**STIX Export**](./APPLICATION_WALKTHROUGH.md#9-stix-export) | Threat Intelligence Pipeline | STIX 2.1 Bundles (observed-data), OpenCTI export, peer transfer | Streamline evidence directly to SOC / SIEM platforms |
| **10** | [**Custom Rules**](./APPLICATION_WALKTHROUGH.md#10-custom-rules) | Guided Rule Authoring | Natural-language "Write in English", YAML import, capability map | Create custom detection rules without coding syntax |
| **11** | [**Alerts & Evidence**](./APPLICATION_WALKTHROUGH.md#11-alerts--evidence) | Tamper-Evident Alerts | Cryptographic backend HMAC checks, severity counts, dry-run mode | Verify alerts with tamper-proof cryptographic proofs |
| **12** | [**Unified Logs**](./APPLICATION_WALKTHROUGH.md#12-unified-logs) | Complete Ground Truth Stream | Merged filterable raw JSON stream across all 5 endpoints | Unabridged forensic query across the whole machine |
| **13** | [**System Health**](./APPLICATION_WALKTHROUGH.md#13-system-health) | Pipeline Operational Health | Events/sec sparklines, Seen vs. Written metrics, queue depth | Ensure pipeline stability with zero silent data loss |
| **14** | [**Settings**](./APPLICATION_WALKTHROUGH.md#14-settings) | Configuration & Retention | Authoritative manifest paths, disk budget coordinator, UX density | Keep storage usage strictly bounded |

---

### How the Architecture Fits Together

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


## 🔍 Core Sensor Fleet

### 1. Process Monitor (`titan_process.exe`)
- **Telemetry Source**: Kernel ETW (`Microsoft-Windows-Kernel-Process`) & native Windows API.
- **Key Capabilities**: Real-time process creation/termination tracking, command-line normalization, digital signature verification, Windows integrity levels, user SID attribution, and parent-child hierarchy reconstruction.
- **7-Stage Trust Filter**: Distinguishes verified system binaries, known user binaries, and unverified anomalous executions.

### 2. Network Monitor (`titan.exe`)
- **Telemetry Source**: Npcap live packet capture & Windows socket attribution.
- **Key Capabilities**: Wire-level protocol decoding for DNS, HTTP, and TLS SNI (ClientHello); per-packet direction (Inbound/Outbound) and duration tracking; automatic flow aggregation and raw PCAP archiving.

### 3. Application Monitor (`application_endpoint.exe`)
- **Telemetry Source**: Application watchlist ETW collector and Windows Event Log streaming.
- **Key Capabilities**: Deep auditing of watched processes and child forks; script-block logging analysis for PowerShell, WMI, and Windows Defender; built-in pattern heuristics for AMSI bypass, credential access, and reflective process injection.

### 4. File Integrity Monitor (`file_test.exe`)
- **Telemetry Source**: Real-time filesystem notifications and baseline state engine.
- **Key Capabilities**: SHA-256 baseline hash comparison across critical directories; detection of file creation, modification, rename, and deletion; intelligent temp-file tracking that promotes churn to durable evidence only if touching executable vectors.

### 5. Port & USB Monitor (`usb_test.exe`)
- **Telemetry Source**: Kernel device listener & raw HID input timing engine.
- **Key Capabilities**: USB device arrival and removal lifecycle tracking; storage volume mount auditing; **BadUSB / HID Injection Detection** via inter-keystroke interval statistical analysis (mean & standard deviation calculations to detect automated keystroke injection).

### 6. Correlation Engine (`correlator.exe`)
- **Telemetry Source**: Aggregates output from all 5 native sensors.
- **Key Capabilities**: Real-time cross-sensor correlation, multi-stage incident graph construction, and timeline reconstruction linking network connections, process spawns, file writes, and USB insertion into a unified attack narrative.

### 7. Custom Rule Engine (`CUSTOM RULE/`)
- **Engine**: Python 3.12 + FastAPI asynchronous service.
- **Key Capabilities**: English-to-Rule natural language guided creation, YAML rule import/export, dynamic collector capability discovery, and live rule matching with alert dispatching.

---

## 🚀 Precompiled Executables

Precompiled, standalone Release binaries are available in the [`executables/`](./executables/) directory:

| Binary | Component | Role |
|---|---|---|
| [`TitanEndpoint.App.exe`](./executables/) | WPF GUI | Unified Security Operator Console & Fleet Manager |
| [`titan_process.exe`](./executables/) | Process Endpoint | Process lifecycle & anomaly monitor |
| [`titan.exe`](./executables/) | Network Endpoint | Npcap packet capture & protocol decoder |
| [`application_endpoint.exe`](./executables/) | Application Endpoint | Application activity & event log decoder |
| [`file_test.exe`](./executables/) | File Endpoint | File Integrity Monitor (FIM) |
| [`usb_test.exe`](./executables/) | Port / USB Endpoint | USB arrival/removal & HID injection guard |
| [`correlator.exe`](./executables/) | Correlator | Cross-endpoint incident correlation engine |

> **Quick Run**: Launch `TitanEndpoint.App.exe` (run as Administrator). The GUI reads `runtime-manifest.json` and manages all endpoint processes automatically.

---

## 🛠 Building from Source

### Prerequisites
- **Operating System**: Windows 10 / 11 / Server (x64)
- **C++ Toolchain**: Visual Studio 2022 / Build Tools with C++20 and CMake
- **.NET SDK**: .NET 8.0 SDK
- **Python**: Python 3.12+ (for Custom Rule service)
- **Driver**: [Npcap](https://npcap.com/) (installed with WinPcap API-compatible mode)

### Automated Clean Build
Run the release build script from PowerShell:
```powershell
.\GUI\scripts\Build-ReleasePackage.ps1
```
This script will:
1. Validate required toolchains (CMake, MSVC, .NET 8, Python).
2. Build all 6 native C++ endpoints using CMake in Release configuration.
3. Build the .NET 8 WPF GUI solution.
4. Execute the regression test suite (`TitanEndpoint.Core.RegressionTests.exe`).
5. Update `runtime-manifest.json` with fresh executable hashes.
6. Verify checksums against `release/CHECKSUMS.sha256`.

---

## 🔒 IPC & Security Architecture

- **Authenticated Control Channels**: Inter-Process Communication (IPC) operates over local Windows Named Pipes (`\\.\pipe\TitanEndpoint_*_Control`) using revision-bound session tokens.
- **Single-Instance Enforcement**: Each endpoint maintains named mutex locks and single-instance verification to prevent multiple collector instances.
- **Durable Evidence Envelopes**: All emitted logs feature an immutable record envelope:
  - `record_id`, `session_id`, `source_file`, `byte_offset`, `content_hash`
- **Threat Intelligence Export**: Built-in support for STIX 2.1 JSON export and integration with OpenCTI threat platforms.

---

## 📂 Repository Layout

```
├── APP/                 # Application Endpoint C++ source code & CMakeLists
├── CORRELATOR/          # Multi-source Correlation Engine C++ source code
├── CUSTOM RULE/         # FastAPI Custom Rule service & behavioral rules
├── DEMO/                # Presentation & live demonstration stimuli scripts
├── FILEEE/              # File Integrity Monitoring (FIM) C++ source code
├── GUI/                 # .NET 8 WPF Dashboard (App, Core, UiTests)
├── NETOWRK ENDPOINT/    # Network Monitor & Npcap packet capture C++ source
├── PORT ENDPOINT/       # USB & HID Injection Guard C++ source code
├── PROCESS ENDPOINT/    # Kernel ETW Process Monitor C++ source code
├── executables/         # Precompiled Release binaries and libraries
├── release/             # Checksums, dependencies, and license inventories
├── tests/               # Automated acceptance, UI, and performance tests
├── runtime-manifest.json# Endpoint configuration, health timeouts, and paths
└── README.md            # Project documentation
```

---

## 📄 License & Attribution

Third-party dependencies and open-source licenses are documented in [`release/THIRD-PARTY-LICENSES.txt`](./release/THIRD-PARTY-LICENSES.txt) and [`release/DEPENDENCIES.md`](./release/DEPENDENCIES.md).
