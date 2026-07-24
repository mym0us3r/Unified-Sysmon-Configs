# Unified Sysmon Configs

**Enterprise-grade telemetry orchestration for Windows (Native & Legacy).  
Optimized for Wazuh, third-party SIEM/XDR platforms, and proactive threat hunting.**

![license](https://img.shields.io/badge/license-GPLv3-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-blue)
![platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%20Server%202025-lightgrey)
![ecosystem](https://img.shields.io/badge/ecosystem-Wazuh-orange)
![tool](https://img.shields.io/badge/tool-Sysmon-red)
![focus](https://img.shields.io/badge/focus-Threat%20Hunting-brightgreen)
![domain](https://img.shields.io/badge/domain-CSIRT-darkblue)

---

## Table of Contents

- [Strategic Overview](#strategic-overview)
- [Behavioral Sensor Architecture](#behavioral-sensor-architecture)
- [Detection Philosophy](#detection-philosophy)
- [Practical Example: Process Creation (EID 1)](#practical-example-process-creation-eid-1)
- [Repository Structure](#repository-structure)
- [Featured Documentation](#featured-documentation-sysmon-as-a-native-resource)
- [Pre-Deployment & Health Checks](#pre-deployment--health-checks)
- [Automated Health Audit](#automated-health-audit-recommended)
- [Wazuh Integration](#wazuh-discover-native-sysmon-integration)
- [Wazuh Ruleset - Native Sysmon Rewrite](#-wazuh-ruleset---native-sysmon-rewrite)
- [Acknowledgments & Credits](#acknowledgments--credits)

---

## Strategic Overview

Endpoint visibility is the cornerstone of modern Detection Engineering. With the release of **Windows 11 (24H2+)**, Sysmon has transitioned into a **Native OS Feature**, fundamentally changing how security teams manage lifecycle, updates, and driver stability.

This repository serves as a centralized hub for production-ready configurations, connecting legacy Sysinternals deployments to the new native integration with full MITRE ATT&CK alignment and Wazuh ruleset coverage.

Legacy Sysmon configurations were traditionally designed around a **"collect-first, filter-later"** model. This often resulted in:

- High event volume (excessive EPS/logging overhead)
- Heavy reliance on SIEM parsing and post-processing
- Limited behavioral context at the endpoint level

**With Sysmon Native, the paradigm shifts:**

> *Filter at the source. Dispatch only high-value telemetry.*

| Mindset | Strategy | Result |
|---|---|---|
| **Legacy** | Collect as much as possible, handle noise at the SIEM | High ingestion cost, analyst fatigue |
| **Native** | Apply intelligence at the endpoint, forward only actionable events | High signal-to-noise, faster triage |

---

## Behavioral Sensor Architecture

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_sensor_arch.jpg?raw=true" alt="Unified Sysmon Configs - Behavioral Sensor Architecture" width="1024px">
  <br>
  <em>Transitioning from Legacy Logging to Sysmon Native Intelligence</em>
</p>

| Dimension | Legacy / Standalone | Sysmon Native (Kernel) | Technical Impact |
|---|---|---|---|
| **Data Pipeline** | Extensive SIEM Parsing | Natively Structured Events | Reduced External Dependencies |
| **Field Quality** | Inconsistent Context | High Fidelity Behavioral Data | More Accurate SIEM Rules |
| **Strategy** | Broad Data Collection | Intelligent Kernel Filtering | Significantly Lower Noise |
| **Detection Type** | IOC-Driven (Hashes/IPs) | Behavior-Driven (TTPs) | Enhanced Defense Against Evasion |
| **Performance Impact** | High SIEM Processing Load | Distributed Endpoint Load | Optimized System Resources |

**What changes in practice:**

- **Structured Events** - Sysmon Native preserves event integrity and structure from kernel to agent
- **Higher Fidelity** - Command-line arguments, parent-child relationships, and process context are significantly more reliable
- **Reduced Noise** - Advanced exclusions silence benign system activity before it leaves the host
- **Behavioral Detection** - Shifts the focus from static IOCs (hashes/IPs) to dynamic TTPs

---

## Detection Philosophy

Instead of merely flagging tools, this configuration focuses on identifying **intent and behavior**:

| Category | What We Hunt | MITRE Techniques |
|---|---|---|
| Suspicious Execution | Encoded/hidden PowerShell, script execution from temp paths | T1059.001, T1059.003 |
| LOLBins Abuse | Living-off-the-land binary misuse | T1218 |
| Credential Access | LSASS memory access, credential dumping tools | T1003.001 |
| Persistence | Registry hijacking, WMI subscriptions, startup abuse | T1547, T1546.003 |
| C2 Indicators | DNS beaconing, non-standard port usage | T1071.004, T1571 |
| Defense Evasion | Process hollowing, ADS creation, timestomping | T1055.012, T1564.004, T1070.006 |

**Operational benefits:**

- **Lower Ingestion Costs** - Drastic reduction in data volume sent to the SIEM/Wazuh
- **Higher Signal-to-Noise Ratio** - Analysts spend time on threats, not logs
- **Enhanced Threat Hunting** - Cleaner data allows for more complex correlation and pivoting
- **MITRE ATT&CK Alignment** - Direct visibility into the adversary playbook

---

## Practical Example: Process Creation (EID 1)

> **Scenario:** Detecting PowerShell abuse with obfuscation flags - T1059.001

### Legacy approach (broad, high noise)

```xml
<ProcessCreate onmatch="include">
  <Image condition="image">powershell.exe</Image>
</ProcessCreate>
```

**The problem:** Fires on every PowerShell invocation - legitimate admin tasks, scripts, IDE integrations. High noise floor, zero behavioral context, constant false positives.

---

### Native approach (behavioral, low noise)

```xml
<RuleGroup name="ProcessCreate-Includes" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="T1059.001-PowerShell-Execution" groupRelation="and">
      <OriginalFileName condition="contains any">powershell.exe;pwsh.exe;powershell_ise.exe</OriginalFileName>
      <CommandLine condition="contains any">-enc;-nop;-w hidden;IEX;Invoke-Expression;DownloadString;FromBase64String;bypass;-ExecutionPolicy</CommandLine>
    </Rule>
  </ProcessCreate>
</RuleGroup>
```

**The gain:** Requires **both** conditions simultaneously via `groupRelation="and"` - fires only when PowerShell is launched with known evasion or obfuscation flags.

### What this detects

| Trigger | Command Example | ATT&CK |
|---|---|---|
| Base64 encoded payload | `powershell -enc SQBFAFgA...` | T1027 |
| Hidden window + no profile | `powershell -nop -w hidden -c ...` | T1059.001 |
| In-memory execution | `powershell IEX (New-Object Net.WebClient).DownloadString(...)` | T1105 |
| Bypass execution policy | `powershell -ExecutionPolicy Bypass -File payload.ps1` | T1059.001 |

### EID 1 field mapping in Wazuh

```json
{
  "data.win.eventdata.image":            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "data.win.eventdata.commandLine":      "powershell -nop -w hidden -enc SQBFAFgA...",
  "data.win.eventdata.originalFileName": "PowerShell.EXE",
  "data.win.eventdata.parentImage":      "C:\\Windows\\explorer.exe",
  "data.win.eventdata.hashes":           "MD5=...,SHA256=...,IMPHASH=...",
  "data.win.system.eventID":             "1"
}
```

> **Noise reduction:** A single `contains any` on `OriginalFileName` alone fires on every PowerShell call. The AND condition cuts that volume by ~90% while preserving detection for actual abuse patterns.

---

## Repository Structure

```
Unified-Sysmon-Configs/
│
├── configs/
│   ├── native/                          # Windows 11 24H2+ · Schema 4.91
│   │   └── sysmon-native.xml
│   └── legacy/                          # Windows 7+ · Sysinternals standalone
│       ├── sysmonconfig-export.xml      # SwiftOnSecurity baseline
│       └── sysmonconfig.xml             # olafhartong/sysmon-modular
│
├── ruleset/
│   └── rules/
│       ├── wazuh-server-4.14/           # Production-verified rules (live environment)
│       ├── wazuh-official-repo/         # Alignment with official Wazuh content
│       └── native-sysmon-rewrite-by-m0us3r/   # ← NEW · Full Native Sysmon rewrite
│           ├── 0595-win-sysmon_rules.xml        #   30 rules · EID 1-29 group tag definitions + routing
│           ├── 0800-sysmon_id_1.xml             #   83 rules · EID 1 Process Creation
│           ├── 0810-sysmon_id_3.xml             #   11 rules · EID 3 Network Connection
│           ├── 0820-sysmon_id_7.xml             #   10 rules · EID 7 Image Load
│           ├── 0830-sysmon_id_11.xml            #   29 rules · EID 11 File Create
│           ├── 0840-sysmon_id_6.xml             #    4 rules · EID 6 Driver Load (BYOVD)
│           ├── 0850-sysmon_process_anomalies.xml #  24 rules · EID 1 Process Anomaly
│           ├── 0860-sysmon_id_13.xml            #   11 rules · EID 13 Registry Value Set
│           ├── 0870-sysmon_id_8.xml             #    5 rules · EID 8 CreateRemoteThread
│           ├── 0880-sysmon_id_9.xml             #    3 rules · EID 9 Raw Access Read
│           ├── 0890-sysmon_id_17_18.xml         #    2 rules · EID 17/18 Pipe Event (C2)
│           ├── 0945-sysmon_id_10.xml            #    4 rules · EID 10 Process Access
│           ├── 0950-sysmon_id_20.xml            #    3 rules · EID 20 WMI Consumer
│           ├── 0955-sysmon_id_24.xml            #    2 rules · EID 24 Clipboard Change (ClickFix)
│           └── 0960-sysmon_id_29.xml            #    2 rules · EID 29 New Executable Detected
│                                                #  223 rules total · 13 EIDs with behavioral coverage
│
├── adv_simulation/                      # Adversary Simulation · Native vs Legacy
│   └── native_vs_legacy.md             # Comparative detection validation report
│
├── scripts/
│   └── Check-SysmonHealth.ps1          # 8-layer automated diagnostic script
│
└── docs/                               # Technical guides, screenshots, PDF
```

| File | Lines | Schema | Operator Style | Model |
|---|---|---|---|---|
| `configs/native/sysmon-native.xml` | +400 | 4.91 | `groupRelation="and"`, `contains any`, `excludes any` | Filter at the source |
| `configs/legacy/sysmonconfig-export.xml` | +1.100 | 4.50 | OR-based include lists (`groupRelation="and"` supported since schema 4.2 but not applied in this file) | Collect-first, filter-later |
| `configs/legacy/sysmonconfig.xml` | +2.700 | 4.90 | OR-based include lists (`groupRelation="and"` supported since schema 4.2 but not applied for these scenarios) | Collect-first, filter-later |

> The native config is 4-7x smaller not because it covers fewer threats, but because `groupRelation="and"` (schema 4.91) eliminates noise at the point of capture. The same EID that requires 50+ exclusion lines in a legacy config is resolved in 10 lines with AND logic in the native config.

**Wazuh ruleset sync:**

```bash
# Copy native rewrite rules to Wazuh manager
cp ruleset/rules/native-sysmon-rewrite-by-m0us3r/*.xml /var/ossec/ruleset/rules/

# Validate - must return zero warnings
/var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i "warning\|error\|critical"
echo "Exit: $?"

# Apply
systemctl restart wazuh-manager
```

---

## Featured Documentation: Sysmon as a Native Resource

<p align="center">
  <a href="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon%20native.pdf">
    <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_tips_tricks.png?raw=true" alt="Sysmon Native Guide Preview" width="600px">
    <br>
    <b>➔ Click here to view the Technical Guide (PDF)</b>
  </a>
</p>

Key insights from the guide:

- **Native Lifecycle Management** - Leveraging KB5077241 for automated updates via Windows Update
- **Enterprise Scalability** - Deployment strategies using DISM and PowerShell for fleet-wide provisioning
- **High-ROI Telemetry** - A curated Top 10 list of critical events for maximum visibility
- **Operational Health Checks** - Procedures for Schema validation and configuration auditing

---

## Pre-Deployment & Health Checks

Verify the Sysmon Native state using multi-layer validation before applying any configuration.

### 1. Feature status (PowerShell)

```powershell
# Check if feature is enabled
Get-WindowsOptionalFeature -Online -FeatureName "Sysmon"

# Quick active/inactive check
$f = Get-WindowsOptionalFeature -Online -FeatureName "Sysmon" -ErrorAction SilentlyContinue
if ($f.State -eq "Enabled") {
    Write-Host "Sysmon Native is ACTIVE" -ForegroundColor Green
} else {
    Write-Host "Sysmon Native is DISABLED" -ForegroundColor Red
}
```

### 2. Feature status (DISM / CMD)

```cmd
Dism /Online /Get-FeatureInfo /FeatureName:Sysmon
```

### 3. Service and driver

```cmd
sc query sysmon
fltmc filters | findstr "Sysmon"
```

Expected service output:
```
SERVICE_NAME: Sysmon
    TYPE               : 10  WIN32_OWN_PROCESS
    STATE              : 4   RUNNING
    WIN32_EXIT_CODE    : 0   (0x0)
    SERVICE_EXIT_CODE  : 0   (0x0)
```

### 4. Applied configuration

```cmd
"C:\Windows\System32\Sysmon.exe" -c
```

Expected output:
```
Service name:       Sysmon
Driver name:        SysmonDrv
Config file:        C:\Windows\System32\Sysmon\config.xml
Config hash:        SHA256=6F5C1404DC97F2CFC72E17CCB5849C339B4AAD2D77FE36D123709219423B3E66
HashingAlgorithms:  MD5,SHA256,IMPHASH
Schema version:     4.91
Sysmon is running.
```

### 5. GUI validation

```
Settings → System → Optional features → More Windows features (opens the classic "Windows Features" dialog, also reachable via `optionalfeatures.exe`) → Sysmon
services.msc → Sysmon → Status: Running | Startup: Automatic
eventvwr.msc → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_gui_check.png?raw=true" alt="Sysmon GUI Verification" width="1024px">
  <br>
  <em>Manual verification of Sysmon Native feature via Optional Features GUI and successful Event Viewer log ingestion</em>
</p>

---

## Automated Health Audit (Recommended)

For deep and automated telemetry validation, use the senior diagnostic script included in `/scripts`. It performs an **8-layer scan** - from binary integrity and digital signature verification to real-time event sampling and registry validation.

<p align="center">
  <a href="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/scripts/Check-SysmonHealth.ps1">
    <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_check.png?raw=true" alt="Check-SysmonHealth Preview" width="800px">
  </a>
</p>

| Layer | Check | What It Validates |
|---|---|---|
| 1 | Windows Optional Feature | Feature state, RestartNeeded |
| 2 | Binary Integrity | `Sysmon.exe` path, version, digital signature (Microsoft chain) |
| 3 | Windows Service | Running state, StartType, PID, ExitCode via WMI |
| 4 | Kernel Driver | `SysmonDrv` status, path, `driverquery` confirmation |
| 5 | Event Log | Enabled state, max size, most recent event timestamp |
| 6 | Configuration XML | Schema version, SHA-256 hash, filter rule count |
| 7 | Event Sample | Last N events with EID, timestamp, process path |
| 8 | Registry Keys | Service, driver and config keys with values |

**Run:**

```powershell
# Standard run - requires Administrator
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1"

# With report exported to Desktop
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1" -ExportReport

# Custom event sample count
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1" -ExportReport -EventSampleCount 20
```

---

## Wazuh Discover: Native Sysmon Integration

Real-world preview of **Microsoft-Windows-Sysmon** (Native) event ingestion - telemetry captured, decoded, and indexed by the Wazuh Manager.

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_wazuh.png?raw=true" alt="Wazuh Native Sysmon Events" width="1024px">
</p>

| Field | Value |
|---|---|
| **Provider** | `Microsoft-Windows-Sysmon` (Official Windows Component) |
| **Key fields** | `data.win.eventdata.targetFilename`, `data.win.eventdata.image` |
| **Rule alignment** | `/ruleset/rules/native-sysmon-rewrite-by-m0us3r/` |
| **Detection scope** | Executable drops, PowerShell execution, lateral movement, persistence |

---

## 🔧 Wazuh Ruleset - Native Sysmon Rewrite

> **Production-validated · Wazuh 4.14.4 · Windows 11 24H2+ (KB5077241) · MITRE ATT&CK v15 · Zero warnings on `wazuh-analysisd -t`**

![rules](https://img.shields.io/badge/rules-223-brightgreen)
![EIDs](https://img.shields.io/badge/EIDs-13-blue)
![anchor](https://img.shields.io/badge/anchor-if__group-orange)
![status](https://img.shields.io/badge/status-production--validated-success)

Complete rewrite of the Wazuh Sysmon detection ruleset from Legacy Sysinternals format to **Sysmon Native** (Windows 11 24H2+ kernel-integrated Sysmon). Every rule was rebuilt from the ground up, tested against live telemetry from a production Wazuh 4.14.4 environment, and validated with zero warnings.

---

### The Core Problem - Why the Migrated Rules Fail on 24H2+

Two independent failure modes - both producing silent, zero-alert results.

**Failure 1 - Load order:** The original `0330-sysmon_rules.xml` used `sysmon.*` field names from a pre-Wazuh 3.8.0 decoder (`if_sid>18100`). That file was correctly rewritten to use `win.eventdata.*` fields and `if_group>sysmon_event1`. However, it also referenced `if_sid>92000` (defined in `0800`), and because `0330` loads before `0800` alphabetically, Wazuh discards those rules silently at load time. Fix: rename to `0850` so it loads after `0800`.

> **Community clarification (rule `184666` and the process-anomaly family):** feedback from the community correctly pointed out that some rules in this cluster - including `184666` - already ship with the correct `if_group>sysmon_event1` anchor in both the official Wazuh repository and the installation package. The anchor was never broken for those specific stock rules. What this rewrite actually fixes on them is the **field name**: the originals check `sysmon.image` (and similar `sysmon.*` fields), the naming used by Wazuh's decoder prior to `eventchannel` support (~2017). That field is never populated when Sysmon is configured with `log_format>eventchannel` - the recommended setup for years, for both Legacy and Native Sysmon. These specific rules have been silently broken out of the box, independent of any Native Sysmon migration. This rewrite migrates them to `win.eventdata.*`, which is what eventchannel telemetry actually populates.
>
> **Note on rule numbering:** rule ID `184666` above refers to this project's own rewritten rule in the process-anomaly family. The Wazuh server's default ruleset also ships a rule numbered `184666` with different logic (the stock `svchost.exe` / `sysmon.image` check described above) - this rewrite reuses that same ID rather than colliding with it by accident, as part of the `184666-184777` numbering range chosen for the process-anomaly family. It is not a duplicate or conflicting definition of the same rule: they are two different rules that happen to share a number by design. This also explains why this project's own `0330` -> `0850` rewrite could independently reference `if_sid>92000` and get silently discarded during early development (see "Failure 1" above), while the stock `184666` - untouched, unrelated code - never had that problem. Same numbering approach as rule `92153` (EID 7) further below.
>
> A related structural change: in the default ruleset, both the anchor rule (`92000`) and its child rules share the same `if_group>sysmon_event1` tag - all siblings under one group, with no explicit hierarchy. This rewrite chains child rules via `if_sid>92000` instead, pointing directly at the anchor, which reduces the risk of an unrelated rule firing just because it shares the same generic group tag.

> **Important clarification:** `win.eventdata.*` fields are not exclusive to Sysmon Native. They have been available with Legacy Sysmon since Wazuh 3.8.0, when the agent is configured with `log_format>eventchannel`. What KB5077241 changed was the **deployment model** (Sysinternals binary to Windows Optional Feature), the **schema version** (4.50 to 4.91, unlocking new capabilities including extended OriginalFileName coverage and nested rule grouping), and the **lifecycle management** (manual updates to Windows Update). The fields and the decoder remain the same.

**Failure 2 - Runtime evaluation path:** All attempts using `if_sid>60000` as a base anchor for the new native detection rules failed silently in production. The Wazuh rule engine walks the tree **depth-first** and stops at rule `61603` (EID dispatcher), never reaching a sibling branch anchored at `60000`. Fix: introduce the anchor `92000` chained through `if_group>sysmon_event1` (reachable from `61603`), then chain the new detection rules to that anchor via `if_sid>92000`.

> **Important clarification:** `if_group>sysmon_event1` is not a new mechanism introduced by this rewrite. It is the same chaining mechanism the default Wazuh ruleset already uses - the stock anchor `92000` and its 82 child rules are all siblings under that same tag, with no explicit parent-child hierarchy between them. What this rewrite changes is the **child-chaining model**: instead of every detection rule sharing the same group tag as a sibling (which means an unrelated rule can fire off that generic tag if its own conditions happen to match), each rule in this ruleset chains via `if_sid>92000`, pointing directly at the anchor. That is a narrower, more auditable dependency graph - not a discovery of `if_group` itself.

```text
Event arrives (Microsoft-Windows-Sysmon/Operational)
  -> 60004  (channel routing)
    -> 61600 (severity INFORMATION)
      -> 61603 (EID 1, assigns runtime group: sysmon_event1)
        -> 92000 (if_group>sysmon_event1 + providerName)                   <- FIRES ✅  [anchor]
          -> 92027 (if_sid>92000 · T1059.001 · PowerShell chain)           <- FIRES ✅
          -> 92057 (if_sid>92000 · T1059.001 · EncodedCommand · level 12)  <- FIRES ✅
```

`if_group` references the **runtime group tag** assigned during event processing at the anchor level - no load-order dependency, no compile-time SID resolution failure.

---

### Rule Count - Legacy vs Native

| File | Legacy | Native | Delta | EID | Coverage |
|---|---|---|---|---|---|
| `0595-win-sysmon_rules.xml` | 56 | 30 | -26 | 1-29 | EventChannel infrastructure routing (dispatch + runtime group assignment only) |
| `0800-sysmon_id_1.xml` | 82 | **83** | +1 | 1 | Process Creation - Native anchor + full detection chain |
| `0810-sysmon_id_3.xml` | 10 | 11 | +1 | 3 | Network Connection |
| `0820-sysmon_id_7.xml` | 7 | 10 | +3 | 7 | Image Load - vaultcli.dll tiered detection |
| `0830-sysmon_id_11.xml` | 28 | 29 | +1 | 11 | File Create |
| `0840-sysmon_id_6.xml` | 0 *(new)* | 4 | +4 | 6 | Driver Load - BYOVD / EDR-killer detection |
| `0850-sysmon_process_anomalies.xml` | 39 *(was 0330)* | 24 | -15 | 1 | Process Anomaly chain (parent/image validation) |
| `0860-sysmon_id_13.xml` | 10 | 11 | +1 | 13 | Registry Value Set |
| `0870-sysmon_id_8.xml` | 4 | 5 | +1 | 8 | CreateRemoteThread |
| `0880-sysmon_id_9.xml` | 0 *(new)* | 3 | +3 | 9 | Raw Access Read - credential access via raw disk |
| `0890-sysmon_id_17_18.xml` | 0 *(new)* | 2 | +2 | 17/18 | Pipe Event - Cobalt Strike named pipe detection |
| `0945-sysmon_id_10.xml` | 3 | 4 | +1 | 10 | Process Access |
| `0950-sysmon_id_20.xml` | 2 | 3 | +1 | 20 | WMI Consumer Activity |
| `0955-sysmon_id_24.xml` | 0 *(new)* | 2 | +2 | 24 | Clipboard Change - ClickFix (T1204.004) detection |
| `0960-sysmon_id_29.xml` | 0 *(new)* | 2 | +2 | 29 | New Executable Detected |
| **GRAND TOTAL** | **241** | **223** | **-18** | **13 EIDs** | |

> **Duplicate rule removal (2026-07-23):** `0595` originally shipped 24 process-anomaly rules (13 parent + 11 "legitimate parent image" silencer children, IDs `61618-61641`) that were byte-for-byte identical - field by field, description included - to `0850`'s `184666-184777` family. Both chained from the same `if_group>sysmon_event1` anchor, so every matching event fired two identical alerts under two different rule IDs. Confirmed by direct diff, not assumption. `0850` is the dedicated file for this detection family (and a superset - it covers 11 additional binaries the `0595` copy never did), so the 24 duplicates were removed from `0595`, which is now infrastructure-only, matching its filename and original scope.

> **Coverage expansion (2026-07-24):** `0840`, `0880`, `0890`, `0955`, and `0960` add behavioral detection for five Event IDs that had **never had dedicated Wazuh coverage** - not in this project's earlier state, and not in Wazuh's own stock ruleset either (confirmed directly against the upstream `wazuh/wazuh-ruleset` repository, which only ever defined group dispatch up to EID 15 and behavioral rules for EID 1). Each addition maps to a technique with significant 2026 real-world prevalence: EID 6 to BYOVD/EDR-killer tooling (54 documented tools abusing 35 signed drivers as of March 2026), EID 24 to ClickFix (T1204.004 - the most common initial-access technique in 2025-2026 threat reporting, used by both APT28/Kimsuky/MuddyWater and ransomware operators), EID 9 to raw-disk credential extraction (SAM/NTDS.dit via Volume Shadow Copy), EID 17/18 to Cobalt Strike named-pipe C2, and EID 29 to new-executable drops. `0595`'s dispatch table was extended from EID 1-23 to EID 1-29 to support this. Full technical writeup, including the two `sysmon-native.xml` bugs found during this expansion, below.

> The delta in `0595` and `0850` reflects removal of **legacy Sysinternals dispatcher rules** (`if_sid>18100` + `sysmon.*` fields) that are architecturally incompatible with the Native pipeline, plus the duplicate removal noted above for `0595`, offset by the five new coverage files. `0800` shows the rewrite kept essentially the same rule volume as the stock ruleset (82 to 83) while restructuring the chaining model from shared `if_group` siblings to explicit `if_sid>92000` parent-child references (see "Failure 2" above). **Net total is 18 rules lower than Legacy while covering 5 more EIDs - consolidation and duplicate elimination outweighing new coverage, not coverage loss.**

---

### File Naming - Load Order Is Critical

Wazuh loads rules alphabetically. The group tag `sysmon_event1` is registered when rule `61603` is processed inside `0595`. Any file referencing `if_group>sysmon_event1` **must load after `0595`**.

```text
0595  <- defines sysmon_event1 group tag (rule 61603)  <- group exists from here
0800  <- 92000 (Native EID 1 anchor: if_group>sysmon_event1)
0810  <- EID 3  · if_group>sysmon_event3
0820  <- EID 7  · if_group>sysmon_event7
0830  <- EID 11 · if_group>sysmon_event_11
0840  <- EID 6  · if_group>sysmon_event6
0850  <- EID 1 process anomaly · if_group>sysmon_event1  <- MUST be > 0595
0860  <- EID 13 · if_group>sysmon_event_13
0870  <- EID 8  · if_group>sysmon_event8
0880  <- EID 9  · if_group>sysmon_event9
0890  <- EID 17/18 · if_group>sysmon_event_17 / sysmon_event_18
0945  <- EID 10 · if_group>sysmon_event_10
0950  <- EID 20 · if_group>sysmon_event_20
0955  <- EID 24 · if_group>sysmon_event_24
0960  <- EID 29 · if_group>sysmon_event_29
```

> The file `0330-sysmon_rules.xml` is **renamed to `0850-sysmon_process_anomalies.xml`**. This is not cosmetic - it is a required architectural change. Naming it `0330` causes 24 rules to be silently discarded at load time.

---

### vaultcli.dll - Tiered Detection Architecture (Rule 92153 · EID 7)

`vaultcli.dll` (Windows Credential Vault Client Library) is a primary target for **T1555 / T1555.004** credential dumping - Mimikatz `vault::list`, `vault::cred` and custom tooling.

> **Important:** The `signed` field in EID 7 describes the **loaded DLL**, not the loading process. `vaultcli.dll` always reports `signed=true / signature=Microsoft Windows` regardless of who loads it. Detection must be based on **loading process path risk**.

| Rule | Level | Trigger | Analyst Action |
|---|---|---|---|
| `92153` | 0 | vaultcli.dll loaded - known OS processes silenced by **full path** | Silent base anchor |
| `92158` | **15** | Loading process path in `Temp` / `AppData` / `Public` / `Downloads` | **CRITICAL** - treat as active credential dump |
| `92159` | 10 | Third-party process outside Windows system paths (e.g. MobaXterm) | **ALERT** - verify expected behavior on this host |

> **Note on rule numbering:** rule ID `92153` above refers to this project's own Tier 0 base anchor (level 0). The Wazuh server's default ruleset also ships a rule numbered `92153` with different logic (a generic path-based Image Load detection, level 10) - this is a pre-existing ID collision between the two rulesets, not a duplicate or conflicting definition of the same rule. It surfaces in the `adv_simulation/native_vs_legacy.md` report, where the default-ruleset `92153` fires independently during Legacy testing. See that report's Finding 6 for the full analysis.

**OS exclusions confirmed via live Windows 11 24H2+ telemetry:**

- `VaultCmd.exe` - legitimate vault management tool
- `svchost`, `lsass`, `explorer`, `LogonUI`, `CredentialUIBroker` - core OS processes
- `backgroundTaskHost`, `taskhostw`, `winlogon` - Windows task and session hosts
- `C:\Windows\SystemApps\...\SearchHost.exe` - Windows 11 Search UI - **full path enforced**
- `C:\Windows\System32\RuntimeBroker.exe` - UWP broker - **full path enforced**

> Full-path exclusions prevent bypass via process name spoofing. A `malware.exe` renamed `SearchHost.exe` in `AppData\Temp` still triggers rule `92158` at level 15.

---

### Dual Provider Visibility - Preserved by Design

This rewrite does **not** replace or suppress EID 4688 (Security-Auditing). Both providers fire simultaneously, delivering complementary visibility layers:

```text
[05:12:46] Rule 67027 | L3  | EID 4688 | Microsoft-Windows-Security-Auditing
[05:12:46] Rule 92057 | L12 | EID 1    | Microsoft-Windows-Sysmon
```

| Provider | Rule | Level | Value |
|---|---|---|---|
| `Microsoft-Windows-Security-Auditing` | 67027 | 3 | Process telemetry - always-on baseline |
| `Microsoft-Windows-Sysmon` | 92000-92083 (0800) · 184666-184777 (0850) · 100600-100801 (0840/0880/0890/0955/0960) | 0-15 | MITRE-aligned behavioral intelligence |

> **EID 4688** = *"who was born"* · **Sysmon EID 1** = *"what it is doing and why it matters"*

---

### MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|---|---|
| **Execution** | T1059, T1059.001, T1059.003, T1059.005, T1059.007, T1047, T1204, T1204.002, T1204.004, T1569.002 |
| **Persistence** | T1543.003, T1546, T1546.003, T1546.011, T1547.001, T1547.006 |
| **Privilege Escalation** | T1068, T1548, T1548.002 |
| **Defense Evasion** | T1006, T1027, T1027.004, T1036, T1036.002, T1036.003, T1070.004, T1112, T1140, T1218, T1562, T1562.001, T1574 |
| **Credential Access** | T1003.001, T1003.002, T1003.003, T1555, T1555.004 |
| **Discovery** | T1018, T1033, T1069, T1082, T1087, T1135, T1518.001 |
| **Lateral Movement** | T1021.001, T1021.002, T1021.004, T1021.006 |
| **Collection** | T1560.001 |
| **Command & Control** | T1071.001, T1095, T1105 |

---

### Escaping Reference - Critical for Rule Maintenance

The Wazuh `windows_eventchannel` decoder doubles backslashes internally:

| Context | PCRE2 Rule | Example |
|---|---|---|
| Stored internally by decoder | - | `C:\\Windows\\System32\\cmd.exe` |
| To match `\` in PCRE2 | `\\\\` | `(?i)\\\\cmd\.exe$` |
| Path separators in field rules | `\\\\` | `[c-z]:\\\\Windows\\\\` |
| Regex metacharacters (`\s \d \b \.`) | `\\` | `\.exe` |

---

### Native Sysmon Rule Redesign for Windows Native Sysmon

```text
0595  EID 1-29: EventChannel Infrastructure - dispatch and runtime group assignment
0800  EID 1:  Process Creation - Native anchor + full behavioral detection chain
0810  EID 3:  Network Connection - Suspicious outbound connection detection
0820  EID 7:  Image Load - DLL load detection with vaultcli.dll tiered architecture
0830  EID 11: File Create - Suspicious file creation in high-risk paths
0840  EID 6:  Driver Load - BYOVD / EDR-killer detection
0850  EID 1:  Process Creation - Parent/Image anomaly detection chain
0860  EID 13: Registry Value Set - Persistence and defense evasion via registry
0870  EID 8:  CreateRemoteThread - Cross-process injection and lateral movement
0880  EID 9:  Raw Access Read - Credential access via direct disk/volume read
0890  EID 17/18: Pipe Event - Cobalt Strike named pipe C2 detection
0945  EID 10: Process Access - LSASS and sensitive process memory access
0950  EID 20: WmiEvent (Consumer Activity) - WMI-based persistence detection
0955  EID 24: Clipboard Change - ClickFix (T1204.004) detection
0960  EID 29: File Executable Detected - New PE drop detection
```

---

### Coverage Expansion - Five EIDs With No Prior Wazuh Detection (2026-07-24)

`0840`, `0880`, `0890`, `0955`, and `0960` add behavioral detection for EID 6, 9, 17/18, 24, and 29 - none of which had dedicated Wazuh rules before, in this project or in Wazuh's own default ruleset. Confirmed directly against the archived upstream `wazuh/wazuh-ruleset` repository: the stock dispatch table stops at EID 15, and stock behavioral coverage exists only for EID 1.

**`sysmon-native.xml` fix required for EID 24 (ClickFix):** the config previously excluded `chrome.exe`, `msedge.exe`, and `firefox.exe` from `ClipboardChange` telemetry. This directly conflicted with detecting ClickFix (T1204.004) - the technique's clipboard write happens via JavaScript *inside the browser process*, so the exclusion silenced the one signal needed to catch it. Fixed in `sysmon-native.xml` v1.3; the Office-app exclusion (unrelated to ClickFix) was kept.

> **Known limitation:** correlating the EID 24 clipboard write with a subsequent EID 1 scripting-interpreter launch (the actual ClickFix signature) is not implemented. Wazuh's `if_matched_sid` mechanism is built for repeated-match/flood detection - its `frequency` attribute has a documented minimum of 2, and a 2021 Wazuh GitHub issue (#7929) confirms undocumented behavior when used without `frequency`/`timeframe`. There is no verified, documented way to express "single event A, then single event B within N seconds" with this mechanism. `0955` ships the anchor/visibility rule only; cross-referencing the two events is a manual Discover/dashboard correlation for now.

**Rule ID range correction:** the first version of this expansion used ad hoc IDs in the `92xxx` range this project already used internally, without checking them against Wazuh's *own* stock ruleset. Two of them (`92500`, `92600`) collided with `0850-audit_rules.xml`, a completely unrelated stock file, causing `wazuh-analysisd -t` to silently keep only the first-loaded definition of six rules. All fifteen new rule IDs were moved to `100000-120000`, the range Wazuh documentation explicitly reserves for custom rules and commits to never using for future stock rules.

| EID | File | Technique | Real-world relevance (2026) |
|---|---|---|---|
| 6 | `0840` | BYOVD / EDR-killer driver loading | 54 documented EDR-killer tools abusing 35 signed vulnerable drivers as of March 2026 (RansomHub, BlackByte, Akira, Scattered Spider, LockBit, Qilin) |
| 9 | `0880` | Raw disk read (SAM/NTDS.dit via VSS) | Classic credential-dumping technique bypassing file-lock monitoring |
| 17/18 | `0890` | Named pipe C2 | Cobalt Strike's default SMB beacon mechanism; catches default pipe names only, evaded by custom Malleable C2 profiles |
| 24 | `0955` | ClickFix (T1204.004) | Most common initial-access technique in 2025-2026 threat reporting (Microsoft Defender Experts: 47% of initial-access cases); used by APT28, Kimsuky, MuddyWater, and ransomware operators (Qilin, Interlock) |
| 29 | `0960` | New executable file drop | Already observed firing in this project's own production testing (`T1204-New-Executable`, LABDESK, 2026-07-23) before a Wazuh rule existed to route it |

---

### Production Validation

```text
Manager  : Wazuh 4.14.4 (Ubuntu)
Agent    : LABDESK · Windows 11 24H2+ (KB5077241)
Analyzer : wazuh-analysisd -t → 0 warnings, exit 0

[05:12:26] Rule 92027 | L4  | EID 1 | T1059.001 · PowerShell spawned PowerShell
[05:12:46] Rule 92057 | L12 | EID 1 | T1059.001 · PowerShell EncodedCommand detected
[05:14:31] Rule 92057 | L12 | EID 1 | T1059.001 · PowerShell EncodedCommand detected
EID 4688 (Rule 67027) firing in parallel - dual provider visibility confirmed ✅
```

---

## Acknowledgments & Credits

This project is built upon the foundational work of the cybersecurity community and official Microsoft resources:

- **[Wazuh Team](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program)** - Premier open-source SIEM/XDR engine and continuous community support
- **[Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program)** Anthony Faruna & Katia Bukcovac - for the patient, detailed feedback that shaped this article into its final form
- **[Microsoft Learn - Enable Sysmon](https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)** - Official guide for native Sysmon enablement
- **[Native Sysmon Announcement](https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112)** - Microsoft Tech Community (Mark Russinovich)
- **[KB5077241](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5077241)** - Official update catalog entry for Sysmon Native integration
- **[Understanding Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)** - Microsoft Windows Security
- **[Olaf Hartong](https://github.com/olafhartong/sysmon-modular)** - Author of *Sysmon-Modular*, key reference for structured configurations and MITRE ATT&CK mapping
- **[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)** - The legendary *sysmon-config* that pioneered the baseline for endpoint visibility
- **[Nextron Systems GmbH](https://github.com/NextronSystems/sysmon-config)** - forked and modified version of @SwiftOnSecurity's sysmon config
- **[TrustedSec - SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide)** - Deep technical reference by Carlos Perez
- **[MITRE ATT&CK](https://attack.mitre.org/)** - The framework that keeps this project honest

---

*GOD, my dog Zeus and I. For the strength, the guard, and the code.* 🐕

---

**Author:** m0us3r · [@mym0us3r](https://github.com/mym0us3r)
