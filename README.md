# 🛡️ Unified Sysmon Configs

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

## 📑 Table of Contents

- [Strategic Overview](#-strategic-overview)
- [Behavioral Sensor Architecture](#-behavioral-sensor-architecture)
- [Detection Philosophy](#-detection-philosophy)
- [Practical Example: Process Creation (EID 1)](#-practical-example-process-creation-eid-1)
- [Repository Structure](#-repository-structure)
- [Featured Documentation](#-featured-documentation-sysmon-as-a-native-resource)
- [Pre-Deployment & Health Checks](#-pre-deployment--health-checks)
- [Automated Health Audit](#-automated-health-audit-recommended)
- [Wazuh Integration](#-wazuh-discover-native-sysmon-integration)
- [Acknowledgments & Credits](#-acknowledgments--credits)

---

## 💡 Strategic Overview

Endpoint visibility is the cornerstone of modern Detection Engineering. With the release of **Windows 11 (24H2+)**, Sysmon has transitioned into a **Native OS Feature**, fundamentally changing how security teams manage lifecycle, updates, and driver stability.

This repository serves as a centralized hub for production-ready configurations, bridging the gap between legacy Sysinternals deployments and the new native integration — with full MITRE ATT&CK alignment and Wazuh ruleset coverage.

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

## 📐 Behavioral Sensor Architecture

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

- **Structured Events** — Sysmon Native preserves event integrity and structure from kernel to agent
- **Higher Fidelity** — Command-line arguments, parent-child relationships, and process context are significantly more reliable
- **Reduced Noise** — Advanced exclusions silence benign system activity before it leaves the host
- **Behavioral Detection** — Shifts the focus from static IOCs (hashes/IPs) to dynamic TTPs

---

## 🎯 Detection Philosophy

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

- **Lower Ingestion Costs** — Drastic reduction in data volume sent to the SIEM/Wazuh
- **Higher Signal-to-Noise Ratio** — Analysts spend time on threats, not logs
- **Enhanced Threat Hunting** — Cleaner data allows for more complex correlation and pivoting
- **MITRE ATT&CK Alignment** — Direct visibility into the adversary playbook

---

## 🔬 Practical Example: Process Creation (EID 1)

> **Scenario:** Detecting PowerShell abuse with obfuscation flags — T1059.001

### Legacy approach (broad, high noise)

```xml
<ProcessCreate onmatch="include">
  <Image condition="image">powershell.exe</Image>
</ProcessCreate>
```

**The problem:** Fires on every PowerShell invocation — legitimate admin tasks, scripts, IDE integrations. High noise floor, zero behavioral context, constant false positives.

---

### Native approach (behavioral, low noise)

```xml
<Rule name="T1059.001-PowerShell-Execution" groupRelation="and">
  <OriginalFileName condition="contains any">
    powershell.exe;pwsh.exe;powershell_ise.exe
  </OriginalFileName>
  <CommandLine condition="contains any">
    -enc;-nop;-w hidden;IEX;Invoke-Expression;DownloadString;FromBase64String;bypass;-ExecutionPolicy
  </CommandLine>
</Rule>
```

**The gain:** Requires **both** conditions simultaneously via `groupRelation="and"` — fires only when PowerShell is launched with known evasion or obfuscation flags.

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

## 🗂️ Repository Structure

```
Unified-Sysmon-Configs/
│
├── configs/
│   ├── native/                          # Windows 11 24H2+ · Schema 4.91
│   │   └── sysmon-win11-native-wazuh.xml
│   └── legacy/                          # Windows 7+ · Sysinternals standalone
│       └── sysmonconfig-export.xml
│
├── ruleset/
│   └── rules/
│       ├── wazuh-server-4.14/           # Production-verified rules (live environment)
│       └── wazuh-official-repo/         # Alignment with official Wazuh content
│
├── scripts/
│   └── Check-SysmonHealth.ps1           # 8-layer automated diagnostic script
│
└── docs/                                # Technical guides, screenshots, PDF
```

| Path | Target Platform | Schema | Operator Style |
|---|---|---|---|
| `configs/native/` | Windows 11 24H2+ · Server 2025 | 4.91 | `contains any`, `excludes any`, `is any`, `groupRelation="and"` |
| `configs/legacy/` | Windows 7+ · Server 2008 R2+ | 4.50 | Standard single-value conditions |

**Wazuh ruleset sync:**

```bash
# Copy custom rules to Wazuh manager
cp ruleset/rules/wazuh-server-4.14/*.xml /var/ossec/etc/rules/

# Validate and restart
/var/ossec/bin/wazuh-logtest
systemctl restart wazuh-manager
```

---

## 📘 Featured Documentation: Sysmon as a Native Resource

<p align="center">
  <a href="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon%20native.pdf">
    <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_tips_tricks.png?raw=true" alt="Sysmon Native Guide Preview" width="600px">
    <br>
    <b>➔ Click here to view the Technical Guide (PDF)</b>
  </a>
</p>

Key insights from the guide:

- **Native Lifecycle Management** — Leveraging KB5077241 for automated updates via Windows Update
- **Enterprise Scalability** — Deployment strategies using DISM and PowerShell for fleet-wide provisioning
- **High-ROI Telemetry** — A curated Top 10 list of critical events for maximum visibility
- **Operational Health Checks** — Procedures for Schema validation and configuration auditing

---

## 🔍 Pre-Deployment & Health Checks

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
Settings → Apps → Optional Features → Installed features → Sysmon
services.msc → Sysmon → Status: Running | Startup: Automatic
eventvwr.msc → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_gui_check.png?raw=true" alt="Sysmon GUI Verification" width="1024px">
  <br>
  <em>Manual verification of Sysmon Native feature via Optional Features GUI and successful Event Viewer log ingestion</em>
</p>

---

## 🩺 Automated Health Audit (Recommended)

For deep and automated telemetry validation, use the senior diagnostic script included in `/scripts`. It performs an **8-layer scan** — from binary integrity and digital signature verification to real-time event sampling and registry validation.

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
# Standard run — requires Administrator
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1"

# With report exported to Desktop
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1" -ExportReport

# Custom event sample count
powershell.exe -ExecutionPolicy Bypass -File ".\Check-SysmonHealth.ps1" -ExportReport -EventSampleCount 20
```

---

## 📊 Wazuh Discover: Native Sysmon Integration

Real-world preview of **Microsoft-Windows-Sysmon** (Native) event ingestion — telemetry captured, decoded, and indexed by the Wazuh Manager.

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_wazuh.png?raw=true" alt="Wazuh Native Sysmon Events" width="1024px">
</p>

| Field | Value |
|---|---|
| **Provider** | `Microsoft-Windows-Sysmon` (Official Windows Component) |
| **Key fields** | `data.win.eventdata.targetFilename`, `data.win.eventdata.image` |
| **Rule alignment** | `/ruleset/rules/wazuh-server-4.14/` |
| **Detection scope** | Executable drops, PowerShell execution, lateral movement, persistence |

---

## 🤝 Acknowledgments & Credits

This project is built upon the foundational work of the cybersecurity community and official Microsoft resources:

- **[Wazuh Team](https://wazuh.com/)** — Premier open-source SIEM/XDR engine and continuous community support
- **[Microsoft Learn — Enable Sysmon](https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)** — Official guide for native Sysmon enablement
- **[Native Sysmon Announcement](https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112)** — Microsoft Tech Community (Mark Russinovich)
- **[KB5077241](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5077241)** — Official update catalog entry for Sysmon Native integration
- **[Olaf Hartong](https://github.com/olafhartong/sysmon-modular)** — Author of *Sysmon-Modular*, key reference for structured configurations and MITRE ATT&CK mapping
- **[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)** — The legendary *sysmon-config* that pioneered the baseline for endpoint visibility
- **[TrustedSec — SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide)** — Deep technical reference by Carlos Perez
- **[MITRE ATT&CK](https://attack.mitre.org/)** — The framework that keeps this project honest

---

*GOD, my dog Zeus and I. For the strength, the guard, and the code.* 🐕

---

**Author:** m0us3r · [@mym0us3r](https://github.com/mym0us3r)
