# TITAN ENDPOINT - Precompiled Binaries

This folder contains the compiled Release binaries for the TITAN ENDPOINT system.

## Binaries Included

| Binary | Component | Description |
|---|---|---|
| `TitanEndpoint.App.exe` | GUI / Dashboard | Unified WPF Fleet Controller & Security Dashboard |
| `titan_process.exe` | Process Endpoint | Process creation, termination, and anomaly detection |
| `titan.exe` | Network Endpoint | Network connection monitor, protocol decoder & capture |
| `application_endpoint.exe` | Application Endpoint | Application activity monitor and telemetry |
| `file_test.exe` | File Endpoint | File Integrity Monitor (FIM) & change tracker |
| `usb_test.exe` | Port / USB Endpoint | USB device connection, removal, and HID guard |
| `correlator.exe` | Correlator | Real-time multi-source event correlation engine |

## Running the Application

Double-click `TitanEndpoint.App.exe` (or run as Administrator) to launch the TITAN ENDPOINT control dashboard.
The application will automatically detect and manage the endpoint processes according to `runtime-manifest.json`.
