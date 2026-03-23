# 🛡️ Unified Sysmon Configs

**Enterprise-grade telemetry orchestration for Windows (Native & Legacy). Optimized for Wazuh, third-party SIEM/XDR platforms, and proactive threat hunting.**

---

## 💡 Strategic Overview
Endpoint visibility is the cornerstone of modern Detection Engineering. With the release of **Windows 11 (24H2+)**, Sysmon has transitioned into a **Native OS Feature**, fundamentally changing how security teams manage lifecycle, updates, and driver stability.

This repository serves as a centralized hub for production-ready configurations, bridging the gap between legacy Sysinternals deployments and the new native integration.

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
sc query sysmon
NOME_DO_SERVIÇO: sysmon
    TIPO                       : 10  WIN32_OWN_PROCESS
    ESTADO                     : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
    CÓDIGO_DE_SAÍDA_DO_WIN32   : 0  (0x0)
    CÓDIGO_DE_SAÍDA_DO_SERVIÇO : 0  (0x0)
    PONTO_DE_VERIFICAÇÃO       : 0x0
    AGUARDAR_DICA              : 0x0

# Verify Driver Attachment (Kernel Minifilter)
fltmc filters | findstr "Sysmon"
SysmonDrv                               7       385201         0

# Display Applied XML Configuration
"C:\Windows\System32\Sysmon.exe" -c
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

Rule configuration (version 4.91):
 - ProcessCreate                      onmatch: include   combine rules using 'Or'
        ParentImage                    filter: image        value: 'sethc.exe'
        ParentImage                    filter: image        value: 'utilman.exe'
        ParentImage                    filter: image        value: 'osk.exe'
        ParentImage                    filter: image        value: 'eventvwr.exe'
        ParentImage                    filter: image        value: 'fodhelper.exe'
        OriginalFileName               filter: contains     value: 'procdump'
        OriginalFileName               filter: is           value: 'TTTracer.exe'
        OriginalFileName               filter: is           value: 'sqldumper.exe'
        ParentImage                    filter: is           value: 'diskshadow.exe'
        OriginalFileName               filter: image        value: 'powershell.exe'
        OriginalFileName               filter: image        value: 'pwsh.exe'
        OriginalFileName               filter: is           value: 'cmd.exe'
        OriginalFileName               filter: is           value: 'wmic.exe'
        ParentImage                    filter: image        value: 'wmiprvse.exe'
        OriginalFileName               filter: is           value: 'schtasks.exe'
        OriginalFileName               filter: is           value: 'at.exe'
        OriginalFileName               filter: image        value: 'tasklist.exe'
        OriginalFileName               filter: image        value: 'qprocess.exe'
        OriginalFileName               filter: is           value: 'certutil.exe'
        OriginalFileName               filter: is           value: 'bitsadmin.exe'
        OriginalFileName               filter: is           value: 'curl.exe'
        OriginalFileName               filter: is           value: 'mshta.exe'
        OriginalFileName               filter: is           value: 'regsvr32.exe'
        OriginalFileName               filter: contains     value: 'rundll32.exe'
        OriginalFileName               filter: is           value: 'msiexec.exe'
        OriginalFileName               filter: is           value: 'vssadmin.exe'
        OriginalFileName               filter: is           value: 'wbadmin.exe'
        OriginalFileName               filter: is           value: 'bcdedit.exe'
        Image                          filter: begin with   value: 'C:\Temp\'
        Image                          filter: begin with   value: 'C:\Users\Public\'
        Image                          filter: begin with   value: 'C:\ProgramData\'
        ParentImage                    filter: image        value: 'winword.exe'
        ParentImage                    filter: image        value: 'excel.exe'
        ParentImage                    filter: image        value: 'powerpnt.exe'
        OriginalFileName               filter: contains     value: 'PsExec'
 - ProcessCreate                      onmatch: exclude   combine rules using 'Or'
        Image                          filter: is           value: 'C:\Windows\System32\svchost.exe'
        Image                          filter: is           value: 'C:\Windows\System32\conhost.exe'
        Image                          filter: begin with   value: 'C:\Program Files\Windows Defender\'
 - FileCreateTime                     onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: end with     value: '.exe'
        Image                          filter: begin with   value: 'C:\Temp'
 - NetworkConnect                     onmatch: include   combine rules using 'Or'
        Image                          filter: image        value: 'powershell.exe'
        Image                          filter: image        value: 'cmd.exe'
        Image                          filter: image        value: 'mshta.exe'
        Image                          filter: image        value: 'regsvr32.exe'
        Image                          filter: image        value: 'rundll32.exe'
        DestinationPort                filter: is           value: '4444'
        DestinationPort                filter: is           value: '31337'
        DestinationPort                filter: is           value: '3389'
        DestinationPort                filter: is           value: '22'
 - NetworkConnect                     onmatch: exclude   combine rules using 'Or'
        Image                          filter: is           value: 'C:\Windows\System32\svchost.exe'
        DestinationHostname            filter: end with     value: '.microsoft.com'
 - ProcessTerminate                   onmatch: include   combine rules using 'Or'
        Image                          filter: begin with   value: 'C:\Users'
        Image                          filter: begin with   value: 'C:\Temp'
 - DriverLoad                         onmatch: exclude   combine rules using 'Or'
        Compound Rule 0001   combine using And
            Signature                      filter: contains     value: 'Microsoft'
            SignatureStatus                filter: is           value: 'Valid'
 - ImageLoad                          onmatch: include   combine rules using 'Or'
        ImageLoaded                    filter: contains     value: 'vaultcli.dll'
        ImageLoaded                    filter: contains     value: 'samlib.dll'
 - CreateRemoteThread                 onmatch: include   combine rules using 'Or'
        TargetImage                    filter: end with     value: '.exe'
 - CreateRemoteThread                 onmatch: exclude   combine rules using 'Or'
        SourceImage                    filter: is           value: 'C:\Windows\System32\svchost.exe'
 - RawAccessRead                      onmatch: include   combine rules using 'Or'
        Device                         filter: begin with   value: '\\.\'
 - ProcessAccess                      onmatch: include   combine rules using 'Or'
        TargetImage                    filter: image        value: 'lsass.exe'
 - ProcessAccess                      onmatch: exclude   combine rules using 'Or'
        SourceImage                    filter: is           value: 'C:\Windows\System32\svchost.exe'
        SourceImage                    filter: end with     value: 'Windows Defender\MsMpEng.exe'
 - FileCreate                         onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: contains     value: '\Startup\'
        TargetFilename                 filter: begin with   value: 'C:\Windows\System32\Tasks\'
        TargetFilename                 filter: begin with   value: 'C:\Windows\Temp\'
        TargetFilename                 filter: begin with   value: 'C:\Users\Public\'
        TargetFilename                 filter: end with     value: '.ps1'
        TargetFilename                 filter: end with     value: '.vbs'
        TargetFilename                 filter: end with     value: '.bat'
 - RegistryEvent                      onmatch: include   combine rules using 'Or'
        TargetObject                   filter: contains     value: '\CurrentVersion\Run'
        TargetObject                   filter: contains     value: '\CurrentControlSet\Services\'
        TargetObject                   filter: contains     value: '\Windows Defender\'
 - FileCreateStreamHash               onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: contains     value: ':'
 - FileCreateStreamHash               onmatch: exclude   combine rules using 'Or'
        TargetFilename                 filter: end with     value: ':Zone.Identifier'
 - PipeEvent                          onmatch: include   combine rules using 'Or'
        PipeName                       filter: contains     value: 'msagent_'
        PipeName                       filter: contains     value: 'MSSE-'
        PipeName                       filter: is           value: 'psexec'
 - WmiEvent                           onmatch: include   combine rules using 'Or'
        Operation                      filter: is           value: 'Created'
 - DnsQuery                           onmatch: include   combine rules using 'Or'
        QueryName                      filter: end with     value: '.tk'
        QueryName                      filter: end with     value: '.ml'
        QueryName                      filter: end with     value: '.ga'
        Image                          filter: image        value: 'powershell.exe'
        Image                          filter: image        value: 'cmd.exe'
 - DnsQuery                           onmatch: exclude   combine rules using 'Or'
        QueryName                      filter: end with     value: 'microsoft.com'
        QueryName                      filter: end with     value: 'windows.com'
        Image                          filter: is           value: 'C:\Windows\System32\svchost.exe'
 - FileDelete                         onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: end with     value: '.exe'
        TargetFilename                 filter: end with     value: '.dll'
        TargetFilename                 filter: end with     value: '.ps1'
 - ClipboardChange                    onmatch: exclude   combine rules using 'Or'
        Image                          filter: end with     value: 'chrome.exe'
        Image                          filter: image        value: 'WINWORD.EXE'
        Image                          filter: image        value: 'EXCEL.EXE'
 - ProcessTampering                   onmatch: include   combine rules using 'Or'
        Image                          filter: end with     value: '.exe'
 - FileDeleteDetected                 onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: end with     value: '.exe'
 - FileExecutableDetected             onmatch: include   combine rules using 'Or'
        TargetFilename                 filter: contains     value: '\Downloads\'
        TargetFilename                 filter: begin with   value: 'C:\Users\Public\'
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


Acknowledgments & Credits

This project is built upon the foundational work of the cybersecurity community and official Microsoft resources:

* **[Wazuh Team](https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/)** – For providing the premier open-source XDR engine and continuous support to the Ambassador program.
* **[Microsoft Learn - Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** – Official home of the Sysinternals suite.
* **[Enable Sysmon Guide](https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)** – Official Microsoft guide on enabling Sysmon as a native resource.
* **[Native Sysmon Functionality](https://techcommunity.microsoft.com/blog/windows-itpro-blog/native-sysmon-functionality-coming-to-windows/4468112)** – Microsoft Tech Community announcement.
* **[Microsoft Update Catalog (KB5077241)](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5077241)** – Official update link for Sysmon Native integration.
* **[Olaf Hartong](https://github.com/olafhartong/sysmon-modular)** – Author of *Sysmon-Modular*. A key reference for structured Sysmon configurations and advanced hunting logic.
* **[SwiftOnSecurity](https://github.com/SwiftOnSecurity)** – For the legendary *sysmon-config*, which pioneered the baseline for endpoint visibility.

---
