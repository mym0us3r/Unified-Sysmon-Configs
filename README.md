# 🛡️ Unified Sysmon Configs

**Enterprise-grade telemetry orchestration for Windows (Native & Legacy). Optimized for Wazuh, third-party SIEM/XDR platforms, and proactive threat hunting.**

![license](https://img.shields.io/badge/license-GPLv3-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-blue)
![platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%20Server%202025-lightgrey)
![ecosystem](https://img.shields.io/badge/ecosystem-Wazuh-orange)
![tool](https://img.shields.io/badge/tool-Sysmon-red)
![focus](https://img.shields.io/badge/focus-Threat%20Hunting-brightgreen)
![domain](https://img.shields.io/badge/domain-CSIRT-darkblue)

---

## 💡 Strategic Overview
Endpoint visibility is the cornerstone of modern Detection Engineering. With the release of **Windows 11 (24H2+)**, Sysmon has transitioned into a **Native OS Feature**, fundamentally changing how security teams manage lifecycle, updates, and driver stability.

This repository serves as a centralized hub for production-ready configurations, bridging the gap between legacy Sysinternals deployments and the new native integration.

This project adopts a Sysmon Native-oriented configuration strategy, moving beyond traditional legacy approaches to leverage the high-fidelity telemetry of modern Windows environments.

Legacy Sysmon configurations were traditionally designed around a "collect-first, filter-later" model. This often resulted in:

* High event volume (Excessive EPS/Logging).
* Heavy reliance on SIEM parsing and post-processing.
* Limited behavioral context at the endpoint level.

## With Sysmon Native, the paradigm shifts to:

*Filter at the source, dispatch only high-value telemetry!*

* Legacy Mindset: Collect as much as possible and handle the noise at the SIEM.
* Native Mindset: Apply intelligence at the endpoint to forward only actionable, high-signal events.

### Practical Example: Process Creation (EID 1)

*Legacy (Standard/Broad Approach)*

`<ProcessCreate onmatch="include">
  <Image condition="image">powershell.exe</Image>
</ProcessCreate>`

The Issue: High noise floor, low intelligence, and constant false positives from legitimate administrative activity.

*Native (Behavioral/Optimized Approach)*

`<ProcessCreate onmatch="include">
  <Rule groupRelation="and">
    <Image condition="image">powershell.exe</Image>
    <CommandLine condition="contains any">
      -enc;-nop;-w hidden;
      IEX;Invoke-Expression;
      DownloadString;
      FromBase64String
    </CommandLine>
  </Rule>
</ProcessCreate>`

The Gain: Massive noise reduction, focus on malicious intent/obfuscation, and precise MITRE ATT&CK (T1059) mapping.

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_sensor_arch.jpg?raw=true" alt="Sysmon GUI Verification Print" width="1024px" style="border: 1px solid #eee;">
  <br>
  <b>Sensor:</b> Legacy vs Native Sensor
</p>

# What Changes in Practice?
* Structured Events: Sysmon Native preserves event integrity and structure from kernel to agent.
* Higher Fidelity: Command-line arguments, parent-child relationships, and process context are significantly more reliable.
* Reduced Noise: Advanced exclusions are designed to silence benign system activity before it leaves the host.
* Behavioral Detection: Shifting the focus from static IOCs (hashes/IPs) to dynamic TTPs (Tactics, Techniques, and Procedures).

## Detection Philosophy - Instead of merely flagging tools, this configuration focuses on identifying:

* Suspicious Execution Patterns (e.g., encoded or hidden PowerShell).
* LOLBins Abuse (Living-off-the-Land Binaries).
* Credential Access Behavior (LSASS memory access/dumping).
* Persistence Mechanisms (Registry hijacking, WMI subscriptions).
* Command & Control (C2) Indicators (DNS beaconing and non-standard port usage).
* Lower Ingestion Costs: Drastic reduction in data volume sent to the SIEM/Wazuh.
* Higher Signal-to-Noise Ratio: Analysts spend time on threats, not logs.
* Enhanced Threat Hunting: Cleaner data allows for more complex correlation and pivoting.
* MITRE ATT&CK Alignment: Direct visibility into the adversary playbook.

---

## 📘 Featured Documentation: Sysmon as a Native Resource

This project includes a specialized technical guide to assist SOC/CSIRT teams in migrating to the native telemetry model.

<p align="center">
  <a href="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon%20native.pdf">
    <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_tips_tricks.png?raw=true" alt="Sysmon Native Guide Preview" width="600px" style="border: 1px solid #eee;">
    <br>
    <b>➔ Click here to view the Technical Guide (PDF)</b>
  </a>
</p>

### Key Insights from the Guide:
* **Native Lifecycle Management:** Leveraging KB5077241 for automated updates via Windows Update.
* **Enterprise Scalability:** Deployment strategies using `DISM` and PowerShell for fleet-wide provisioning.
* **High-ROI Telemetry:** A curated "Top 10" list of critical events for maximum visibility.
* **Operational Health Checks:** Procedures for Schema validation and configuration auditing.

---

## 🔍 Pre-Deployment & Health Checks

Verify the Sysmon Native state using these multi-layer validation methods to ensure telemetry integrity.

### PowerShell Method (Automation & Audit)
* **PowerShell: Check feature availability and status** - Ideal for remote execution and fleet-wide health auditing:
  
``` > Get-WindowsOptionalFeature -Online -FeatureName "Sysmon"``` 

* **Rapid "Active/Inactive" check**

` > $sysmonFeature = Get-WindowsOptionalFeature -Online -FeatureName "Sysmon" -ErrorAction SilentlyContinue
if($sysmonFeature.State -eq "Enabled") {
     Write-Host "Sysmon Native is ACTIVE" -ForegroundColor Green
} else {
     Write-Host "Sysmon Native is DISABLED" -ForegroundColor Red
}`

---

* **DOS: Check Feature Status via DISM** - Essential for verifying driver attachment to the storage stack and service registration:

``` > Dism /Online /Get-FeatureInfo /FeatureName:Sysmon```

* **Check Service Registration**

``` > sc query sysmon```

> NOME_DO_SERVIÇO: sysmon
    TIPO                       : 10  WIN32_OWN_PROCESS
    ESTADO                     : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
    CÓDIGO_DE_SAÍDA_DO_WIN32   : 0  (0x0)
    CÓDIGO_DE_SAÍDA_DO_SERVIÇO : 0  (0x0)
    PONTO_DE_VERIFICAÇÃO       : 0x0
    AGUARDAR_DICA              : 0x0*

* **Verify Driver Attachment (Kernel Minifilter)**
``` > fltmc filters | findstr "Sysmon" ```

SysmonDrv                               7       385201         0

* **Display Applied XML Configuration**
``` > "C:\Windows\System32\Sysmon.exe" -c```

Current configuration:
 - Service name:                  Sysmon
 - Driver name:                   SysmonDrv
 - Config file:                   C:\Windows\System32\Sysmon\config.xml
 - Config hash:                   SHA256=6F5C1404DC97F2CFC72E17CCB5849C339B4AAD2D77FE36D123709219423B3E66
 - HashingAlgorithms:             MD5,SHA256,IMPHASH
 - Network connection:            enabled
 - Archive Directory:             \Sysmon\
 - Image loading:                 enabled
 - CRL checking:                  disabled
 - DNS lookup:                    enabled
Rule configuration (version 4.91)
Sysmon is running.

* **C. Graphical User Interface (GUI)**
Manual verification steps for localized troubleshooting:
Optional Features:

```Open Settings > System > Optional Features``` and ensure Sysmon is present in the "Installed features" list.

```Services: Open services.msc``` and verify the Sysmon service is "Running" and set to "Automatic".

* **Event Viewer & Validation:** Confirm log ingestion at:

```Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.``` 

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_gui_check.png?raw=true" alt="Sysmon GUI Verification Print" width="1024px" style="border: 1px solid #eee;">
  <br>
  <b>Windows Check:</b> Manual verification of Sysmon Native feature via Optional Features GUI and successful Event Viewer log ingestion.
</p>

### Repository Architecture 

# Telemetry Configurations
/configs/native: Optimized XML schemas specifically tuned for the Windows 11 Native Sysmon resource.

/configs/legacy: Hardened, reliable baselines for traditional sysmon.exe (Sysinternals) deployments.

# Detection Logic (Wazuh Ruleset)
* **ruleset/rules/wazuh-server-4.14**: Production-verified rules extracted from a live Wazuh environment.
* **ruleset/rules/wazuh-official-repo**: Alignment with the latest official Wazuh security content.

# Operational Workflow
* **Select Baseline**: Choose the configuration from /configs based on your Windows version (Native vs. Legacy).
* **Deployment**: Utilize native provisioning methods (DISM/PowerShell) as detailed in the Technical Guide.
* **Rule Alignment**: Synchronize your ```/var/ossec/etc/rules/``` with the custom rulesets provided in this repo to eliminate telemetry blind spots.

---

## [Automated Health Audit](https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/scripts/Check-SysmonHealth.ps1) (Recommended)

For deep and automated telemetry validation, use the senior diagnostic script included in this repository. It performs an 8-layer scan, ranging from binary integrity to real-time event sampling.

### Script Preview:
![Sysmon Check Preview](https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_check.png?raw=true)

### How to run:
1. Navigate to the [`/scripts`](https://github.com/mym0us3r/Unified-Sysmon-Configs/tree/main/scripts) folder.
2. Run PowerShell as **Administrator**.
3. Run the command below to view the full diagnostic and generate an optional report on your Desktop:
```powershell
.\Check-SysmonHealth.ps1 -EventSampleCount 15 -ExportReport
```
---

## 📊 Wazuh Discover: Native Sysmon Integration

Below is a real-world preview of **Microsoft-Windows-Sysmon** (Native) event ingestion. The telemetry is successfully captured, decoded, and indexed by the Wazuh Manager, providing high-fidelity visibility into PowerShell processes and file system activities.

![Wazuh Native Sysmon Events](https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_wazuh.png?raw=true)

### 🔍 Integration Highlights:
* **Provider**: `Microsoft-Windows-Sysmon` (Official Windows Component).
* **Decoded Data**: Full visibility into `data.win.eventdata.targetFilename` and `data.win.eventdata.image`.
* **Security Context**: Automated detection of executable file drops and PowerShell script execution in real-time.

---

### Community - Acknowledgments & Credits:

This project is built upon the foundational work of the cybersecurity community and official Microsoft resources:

* **[Wazuh Team](https://wazuh.com/)** – For providing the premier open-source SIEM/XDR engine and continuous support to the community :)
* **[Microsoft Learn - Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** – Official home of the Sysinternals suite.
* **[Enable Sysmon Guide](https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)** – Official Microsoft guide on enabling Sysmon as a native resource.
* **[Native Sysmon Functionality](https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112)** – Microsoft Tech Community announcement.
* **[Microsoft Update Catalog (KB5077241)](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5077241)** – Official update link for Sysmon Native integration.
* **[Olaf Hartong](https://github.com/olafhartong/sysmon-modular)** – Author of *Sysmon-Modular*. A key reference for structured Sysmon configurations and advanced hunting logic.
* **[SwiftOnSecurity](https://github.com/SwiftOnSecurity)** – For the legendary *sysmon-config*, which pioneered the baseline for endpoint visibility.

--- 

### GOD, my dog Zeus and I. 
*For the strength, the guard, and the code* :) 

---
