# TITAN ENDPOINT — Dependency Inventory
Updated: 2026-08-03

This document lists all runtime and build-time dependencies for the TITAN ENDPOINT product.
It is generated as part of the FORU.TXT Part 6 release engineering gate ("Produce a reproducible
clean-build script and dependency/license/checksum inventory").

---

## Runtime Dependencies (Required on the Operator Machine)

| Dependency | Version Required | Purpose | Distribution |
|------------|-----------------|---------|--------------|
| Windows 10 version 1903 or later (x64) | 19H1+ | Operating system | User-provided |
| .NET 8 Desktop Runtime (Windows) | 8.0.x | Hosts TitanEndpoint.App.exe (WPF) | [microsoft.com/dotnet](https://dotnet.microsoft.com/download/dotnet/8) |
| Npcap | 1.79 or later | Network packet capture for the Network endpoint | [npcap.com](https://npcap.com) |
| Visual C++ Redistributable 2022 x64 | 14.x | Runtime for native C++ endpoints | [visualstudio.microsoft.com](https://aka.ms/vs/17/release/vc_redist.x64.exe) |
| Python 3.10 or later (64-bit) | 3.10+ | Custom Rule backend (desktop.py, watcher\main.py) | [python.org](https://www.python.org/downloads/) |
| Python package: openai | ≥ 1.0 | LLM rule authoring path (YAML path does not require it) | pip (see CUSTOM RULE\requirements.txt) |
| Python package: pyyaml | ≥ 6.0 | YAML rule parsing | pip |
| Python package: cryptography | ≥ 41.0 | HMAC alert integrity | pip |

> **Note:** The YAML rule authoring path (WRITE/IMPORT YAML) does **not** require OpenAI API access
> or a network connection. It is a deterministic, non-LLM path. The English authoring path
> (WRITE IN ENGLISH) requires OpenAI API access; if quota or API access is unavailable, only the
> YAML path will function. TITAN does not claim automatic degradation to YAML mode — the operator
> must select YAML mode explicitly when LLM access is absent.

---

## Build-Time Dependencies (Required on the Build Machine)

| Dependency | Version | Purpose |
|------------|---------|---------|
| .NET SDK 8 | 8.0.x | Builds TitanEndpoint.App and TitanEndpoint.Core |
| CMake | 3.26 or later | Builds all six native C++ endpoints |
| Visual Studio 2022 Build Tools (MSVC v143) | 17.x | C++ compiler for native endpoints |
| Windows SDK | 10.0.22621 or later | Win32/ETW/IOCTL APIs used by native endpoints |
| Python 3.10 or later | 3.10+ | Custom Rule Python test suite (pytest) |
| pytest | ≥ 7.0 | Custom Rule test runner |
| Npcap SDK | 1.79 or later | Network endpoint compilation (Npcap headers/libs) |
| PowerShell 7 or later | 7.x | Build and acceptance scripts |

---

## Native Endpoint Dependency Detail

### Process Endpoint (PROCESS ENDPOINT\titan_fixed\)
- Win32 API: CreateToolhelp32Snapshot, OpenProcess, QueryInformationJobObject
- ETW: EtwStartTrace, EventWriteEx
- No external library dependencies beyond the Windows SDK.

### Network Endpoint (NETOWRK ENDPOINT\)
- Npcap (wpcap.dll, packet.dll) for live capture.
- Windows Filtering Platform (WFP) for socket attribution.
- Npcap SDK headers at compile time.

### Application Endpoint (APP\src\)
- Win32 API: CreateToolhelp32Snapshot, EnumWindows, QueryFullProcessImageName.
- No external library dependencies.

### File Endpoint (FILEEE\)
- ReadDirectoryChangesW, FSCTL_GET_OBJECT_ID.
- Windows CryptAPI for file hashing fallback.

### Port/USB Endpoint (PORT ENDPOINT\)
- SetupAPI (setupapi.dll), Device Notification (RegisterDeviceNotification).
- WMI for device metadata (IWbemServices).

### Correlator (CORRELATOR\)
- No external library dependencies beyond the Windows SDK.
- Named-pipe IPC (server side, all endpoints).

---

## GUI Dependency Detail (.NET)

The NuGet packages below are restored automatically by `dotnet restore`:

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| Microsoft.Windows.SDK.BuildTools | 10.0.x | MIT | UI Automation in test project |
| System.Windows.Automation (via WindowsBase) | Built into .NET 8 WPF | MIT | UI Automation pattern support |

> The WPF framework (System.Windows.*) is part of .NET 8 and ships under the MIT license.
> No third-party UI framework or commercial UI control library is used.

---

## Optional / Development-Only Dependencies

| Dependency | Purpose |
|------------|---------|
| Wireshark (reference, not shipped) | Protocol dissector reference for Network endpoint comparison |
| Git | Source control; required by Generate-RuntimeManifest.ps1 for commit hash tagging |
| PowerShell module: Pester | Optional: local unit tests for acceptance PowerShell scripts |

---

## Version Pinning Policy

- Native endpoints and the GUI are versioned together and released as a matched set.
- The runtime-manifest.json SHA-256 hashes ensure that a GUI build cannot start a mismatched
  native binary without explicit failure.
- Npcap must be updated when the Network endpoint ships a new pcap API call. This document
  must be updated whenever a dependency version floor changes.

---

*This file must be reviewed and updated for every release. Do not ship a release without
verifying that all version floors, license identifiers, and distribution URLs are current.*
