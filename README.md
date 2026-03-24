# 🛡️ Unified Sysmon Configs

**Enterprise-grade telemetry orchestration for Windows (Native & Legacy). Optimized for Wazuh, third-party SIEM/XDR platforms, and proactive threat hunting.**

---

## 💡 Strategic Overview
Endpoint visibility is the cornerstone of modern Detection Engineering. With the release of **Windows 11 (24H2+)**, Sysmon has transitioned into a **Native OS Feature**, fundamentally changing how security teams manage lifecycle, updates, and driver stability.

This repository serves as a centralized hub for production-ready configurations, bridging the gap between legacy Sysinternals deployments and the new native integration.

![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%20Server%202025-lightgrey)
![Wazuh](https://img.shields.io/badge/ecosystem-Wazuh%20Ambassador-orange)
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

### A. PowerShell Method (Automation & Audit)
Ideal for remote execution and fleet-wide health auditing:
```powershell
# Check feature availability and status
> Get-WindowsOptionalFeature -Online -FeatureName "Sysmon"

FeatureName      : Sysmon
DisplayName      : Sysmon
Description      : Enables the Sysmon tool that monitors and logs specified system activity to the Windows event log
RestartRequired  : Possible
State            : Enabled
CustomProperties :
                   ServerComponent\Description : Enables the Sysmon tool that monitors and logs specified system activity to the
                   Windows event log
                   ServerComponent\DisplayName : Sysmon
                   ServerComponent\Id : 1337
                   ServerComponent\Type : Feature
                   ServerComponent\UniqueName : Sysmon
                   ServerComponent\Deploys\Update\Name : Sysmon```

# Rapid "Active/Inactive" check
$sysmonFeature = Get-WindowsOptionalFeature -Online -FeatureName "Sysmon" -ErrorAction SilentlyContinue
if($sysmonFeature.State -eq "Enabled") { 
    Write-Host "Sysmon Native is ACTIVE" -ForegroundColor Green 
} else { 
    Write-Host "Sysmon Native is DISABLED" -ForegroundColor Red 
}

```

### B. Command Line (CLI) & Kernel Validation
Essential for verifying driver attachment to the storage stack and service registration:
```DOS
# Check Feature Status via DISM
Dism /Online /Get-FeatureInfo /FeatureName:Sysmon
Ferramenta de Gerenciamento e Manutenção de Imagens de Implantação
Versão: 10.0.26100.5074
Versão da Imagem: 10.0.26200.8039
Informações do recurso:
Nome do recurso : Sysmon
Nome para Exibição : Sysmon
Descrição : Enables the Sysmon tool that monitors and logs specified system activity to the Windows event log
Reinicialização Necessária : Possible
Estado : Habilitado
Propriedades Personalizadas:
ServerComponent\Description : Enables the Sysmon tool that monitors and logs specified system activity to the Windows event log
ServerComponent\DisplayName : Sysmon
ServerComponent\Id : 1337
ServerComponent\Type : Feature
ServerComponent\UniqueName : Sysmon
ServerComponent\Deploys\Update\Name : Sysmon
A operação foi concluída com êxito.

# Check Service Registration
> sc query sysmon
NOME_DO_SERVIÇO: sysmon
    TIPO                       : 10  WIN32_OWN_PROCESS
    ESTADO                     : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
    CÓDIGO_DE_SAÍDA_DO_WIN32   : 0  (0x0)
    CÓDIGO_DE_SAÍDA_DO_SERVIÇO : 0  (0x0)
    PONTO_DE_VERIFICAÇÃO       : 0x0
    AGUARDAR_DICA              : 0x0

# Verify Driver Attachment (Kernel Minifilter)
> fltmc filters | findstr "Sysmon"
SysmonDrv                               7       385201         0

# Display Applied XML Configuration
> "C:\Windows\System32\Sysmon.exe" -c
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
..
Sysmon is running.

```

### C. Graphical User Interface (GUI)
Manual verification steps for localized troubleshooting:
Optional Features: 
```Open Settings > System > Optional Features``` and ensure Sysmon is present in the "Installed features" list.

```Services: Open services.msc``` and verify the Sysmon service is "Running" and set to "Automatic".

Event Viewer: Confirm log ingestion at: ```Applications and Services Logs > Microsoft > Windows > Sysmon > Operational```.

3. **Event Viewer & Validation:** Confirm log ingestion at: `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.

<p align="center">
  <img src="https://github.com/mym0us3r/Unified-Sysmon-Configs/blob/main/docs/sysmon_gui_check.png?raw=true" alt="Sysmon GUI Verification Print" width="1024px" style="border: 1px solid #eee;">
  <br>
  <b>Figure 1:</b> Manual verification of Sysmon Native feature via Optional Features GUI and successful Event Viewer log ingestion.
</p>

### Repository Architecture 

# Telemetry Configurations
/configs/native: Optimized XML schemas specifically tuned for the Windows 11 Native Sysmon resource.

/configs/legacy: Hardened, reliable baselines for traditional sysmon.exe (Sysinternals) deployments.

# Detection Logic (Wazuh Ruleset)
* **/ruleset/wazuh-server-4.14**: Production-verified rules extracted from a live Wazuh environment.
* **/ruleset/wazuh-official-repo**: Alignment with the latest official Wazuh security content.

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

### Community - Acknowledgments & Credits:

This project is built upon the foundational work of the cybersecurity community and official Microsoft resources:

* **[Wazuh Team](https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/)** – For providing the premier open-source XDR engine and continuous support to the Ambassador program.
* **[Microsoft Learn - Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** – Official home of the Sysinternals suite.
* **[Enable Sysmon Guide](https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)** – Official Microsoft guide on enabling Sysmon as a native resource.
* **[Native Sysmon Functionality](https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112)** – Microsoft Tech Community announcement.
* **[Microsoft Update Catalog (KB5077241)](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5077241)** – Official update link for Sysmon Native integration.
* **[Olaf Hartong](https://github.com/olafhartong/sysmon-modular)** – Author of *Sysmon-Modular*. A key reference for structured Sysmon configurations and advanced hunting logic.
* **[SwiftOnSecurity](https://github.com/SwiftOnSecurity)** – For the legendary *sysmon-config*, which pioneered the baseline for endpoint visibility.

---
