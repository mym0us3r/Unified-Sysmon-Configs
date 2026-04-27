# Native vs Legacy Sysmon - Adversary Simulation Report

**Comparative Detection Validation: Sysmon Native (schema 4.91) vs Sysmon Legacy (schema 4.90)**

![status](https://img.shields.io/badge/status-production--validated-success)
![wazuh](https://img.shields.io/badge/Wazuh-4.14.4-orange)
![sysmon](https://img.shields.io/badge/Sysmon-Native%204.91-red)
![mitre](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-blue)
![platform](https://img.shields.io/badge/platform-Windows%2011%2024H2%2B-lightgrey)

**Author:** [@mym0us3r](https://github.com/mym0us3r)
**Date:** April 26, 2026  
**Repository:** https://github.com/mym0us3r/Unified-Sysmon-Configs  
**Environment:** Wazuh 4.14.4 - Windows 11 24H2+ Build 26200 - Sysmon Native engine schema 4.91

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Test Environment](#test-environment)
- [Attack Scenarios](#attack-scenarios)
- [Phase 1 - Native Sysmon Results](#phase-1---native-sysmon-config-results)
- [Phase 2 - Legacy Sysmon Results](#phase-2---legacy-sysmon-config-results)
- [Comparative Results Matrix](#comparative-results-matrix)
- [Key Findings](#key-findings)
- [Conclusion](#conclusion)
- [Greetz](#greetz)

---

## Executive Summary

This report documents a structured adversary simulation comparing detection coverage between two Sysmon configurations running on the same endpoint under the same Wazuh 4.14.4 environment. Three attack scenarios were executed identically under each configuration. The results expose fundamental architectural differences between the two models - not just in what they detect, but in **where the detection intelligence resides**.

The Native Sysmon configuration (`sysmon-native.xml`, schema 4.91) filters at the source using `groupRelation="and"` logic, delivering high-fidelity behavioral telemetry before events reach the SIEM. The Legacy configuration (`sysmonconfig.xml`, olafhartong/sysmon-modular, schema 4.90) operates on a collect-first model anchored on known-bad lists - known parent images, known DLL names, known command-line patterns.

> **Important clarification:** `groupRelation="and"` has been supported by the Sysmon schema since version 4.2 (Sysmon v9.0, 2019), as documented by Olaf Hartong at Derbycon 2019. The distinction between Phase 1 and Phase 2 is not a schema capability gap - it is a **configuration design choice**. The legacy config file (`sysmonconfig.xml`) does not apply AND logic for the tested scenarios. When the attacker uses an unlisted vector, the Legacy config produces zero telemetry.

> **Security fix identified during testing:** Rule `92153` used name-only process exclusions (`\\\\svchost\.exe$`), creating a bypass surface. Any malicious binary renamed `svchost.exe` in any path inherited the OS process exclusion and never reached Tier 1 detection. The fix enforces full-path exclusions under `Windows\System32` and `Windows\SysWOW64`. File `0820-sysmon_id_7.xml` updated and published to the repository on April 26, 2026.

---

## Test Environment

| Parameter | Value |
|---|---|
| **SIEM** | Wazuh 4.14.4 (Ubuntu) |
| **Endpoint** | Win-Dell-10 - Windows 11 24H2+ (Build 26200) |
| **Sysmon engine** | Native (KB5077241) - schema 4.91 |
| **Phase 1 config** | `configs/native/sysmon-native.xml` |
| **Phase 1 ruleset** | `ruleset/rules/native-sysmon-rewrite-by-m0us3r/` |
| **Phase 2 config** | `configs/legacy/sysmonconfig.xml` (olafhartong/sysmon-modular) |
| **Phase 2 ruleset** | `ruleset/rules/wazuh-server-4.14/ default install` |
| **Agent config** | `log_format: eventchannel` - `Microsoft-Windows-Sysmon/Operational` |

---

## Attack Scenarios

### Scenario 1 - Masqueraded PowerShell (T1036 + T1059.001)

**Attack:** `powershell.exe` copied to `C:\Users\kr\AppData\Local\Temp\svchost.exe` and executed via `cmd.exe` with `-nop -enc` flags and a Base64-encoded payload.

```cmd
copy "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\Users\kr\AppData\Local\Temp\svchost.exe"

"C:\Users\kr\AppData\Local\Temp\svchost.exe" -nop -enc "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUABvAHcAZQByAFMAaABlAGwAbAAgAE0AYQBzAGsAZQBkACcA"
```

> Decoded payload: `Write-Host 'PowerShell Masked'`

---

### Scenario 2 - LOLBin Execution via Non-Standard Parent (T1137 + T1059.001)

**Attack:** `svchost.exe` fake (PowerShell renamed) executing `Start-Process powershell.exe` with obfuscation flags from `AppData\Local\Temp` - simulating LOLBin spawned by a non-standard parent process.

```cmd
cd "C:\Users\kr\AppData\Local\Temp"
svchost.exe -nop -c "Start-Process powershell.exe -ArgumentList '-nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVAAxADEAMwA3AC0AVABlAHMAdAAnAA=='"
```

---

### Scenario 3 - Credential Vault DLL Load from High-Risk Path (T1555.004)

**Attack:** `svchost.exe` fake loading `vaultcli.dll` from `AppData\Local\Temp` via P/Invoke (`LoadLibrary`) - simulating credential dumping via Windows Credential Manager.

```cmd
cd "C:\Users\kr\AppData\Local\Temp"
svchost.exe -nop -c "$a=Add-Type -MemberDefinition '[DllImport(""kernel32.dll"")] public static extern IntPtr LoadLibrary(string s);' -Name L -PassThru; $a::LoadLibrary('C:\Users\kr\AppData\Local\Temp\vaultcli.dll')"
```

---

## Phase 1 - Native Sysmon Config Results

> **Config active:** `sysmon-native.xml` (schema 4.91) - `groupRelation="and"` applied at the source - filter-first model

### Scenario 1 - Masqueraded PowerShell

Rule `61618` fired at **level 12** (T1055). The Sysmon Native config captured the process through behavioral context: high-risk execution path, non-standard parent process (`cmd.exe`), and real binary identity exposed via `OriginalFileName=PowerShell.EXE` from the PE header. The process name is `svchost.exe` - legacy logic anchored on `Image=powershell.exe` would have produced zero alerts.

```
rule.id         : 61618
rule.level      : 12
mitre           : T1055
image           : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
originalFileName: PowerShell.EXE
parentImage     : C:\\Windows\\System32\\cmd.exe
```

### Scenario 2 - LOLBin via Non-Standard Parent

Rule `92027` fired at **level 4** (T1059.001). Telemetry captured `parentImage=powershell.exe` and `image=powershell.exe` with full fidelity. Detection was based on behavioral pattern - process creating another process with obfuscation flags - not on a static signature.

```
rule.id    : 92027
rule.level : 4
mitre      : T1059.001
image      : C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
parentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
```

### Scenario 3 - Credential Vault DLL Load

Rule `92158` fired at **level 15 - CRITICAL** (T1555.004). The tiered detection architecture worked as designed: the process in `AppData\Local\Temp` was not silenced by Tier 0 and escalated to Tier 1.

```
rule.id    : 92158
rule.level : 15 (CRITICAL)
mitre      : T1555, T1555.004
image      : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
imageLoaded: C:\\Users\\kr\\AppData\\Local\\Temp\\vaultcli.dll
```

> **Security fix applied:** The previous version of rule `92153` used `\\\\svchost\.exe$` (name only). A malicious binary named `svchost.exe` in `AppData\Local\Temp` bypassed Tier 0 and never reached Tier 1. Fix: full-path exclusions enforced under `Windows\System32` and `Windows\SysWOW64`. Published to repository on April 26, 2026.

---

## Phase 2 - Legacy Sysmon Config Results

> **Config active:** `sysmonconfig.xml` (olafhartong/sysmon-modular schema 4.90) - collect-first, OR-based include lists.  
> **Note:** Schema 4.90 supports `groupRelation="and"` (available since schema 4.2 / Sysmon v9.0, 2019). The detection gaps below reflect the **design choices of the legacy config file**, not a schema limitation.

### Scenario 1 - Masqueraded PowerShell

The legacy config **captured the event**. `OriginalFileName=PowerShell.EXE` was present in the telemetry. Rules `61618` (L12), `92213` (L15), and `92151` (L12) fired via the server-side ruleset.

**Critical distinction:** detection occurred because the server ruleset processed the raw event - not because the endpoint config applied behavioral logic. Without the native ruleset active on the server, this event would have been discarded in noise. The legacy model depends on SIEM intelligence, not sensor intelligence.

```
rule.id    : 61618 / 92213 / 92151
rule.level : 12 / 15 / 12
image      : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
originalFileName: PowerShell.EXE
```

### Scenario 2 - LOLBin via Non-Standard Parent

**Zero EID 1 generated on the endpoint.**

The legacy config uses `ProcessCreate onmatch="include"` based on known `ParentImage` attack vectors:

```xml
<ParentImage condition="image">sethc.exe</ParentImage>
<ParentImage condition="image">utilman.exe</ParentImage>
<ParentImage condition="image">osk.exe</ParentImage>
<ParentImage condition="image">Magnify.exe</ParentImage>
<ParentImage condition="image">DisplaySwitch.exe</ParentImage>
```

A process executing from `AppData\Local\Temp` with `cmd.exe` as parent satisfies no include rule. The attack produces no telemetry.

```
EID 1 generated : 0
Alerts fired    : 0
Reason          : ProcessCreate includes based on known ParentImage vectors only.
                  svchost.exe from AppData\Local\Temp matches no include condition.
                  AND logic is available in schema 4.90 but not implemented here.
```

### Scenario 3 - Credential Vault DLL Load

**Zero EID 7 generated on the endpoint.**

The legacy config uses `ImageLoad onmatch="include"` with a specific DLL list - `amsi.dll`, `clr.dll`, `bitsproxy.dll`, `system.management.automation.dll`. `vaultcli.dll` is completely absent from the list.

```
EID 7 generated : 0
Alerts fired    : 0
Reason          : ImageLoad include list does not contain vaultcli.dll.
                  No rule covers credential vault DLL access by process path context.
```

> **Additional observation during Phase 2:** Rule `92041` fired over 60 consecutive times for `reg.exe` spawned by `PwmTower.exe` (Trend Micro Password Manager). This is the collect-first model in production: legitimate software activity generates sustained alert volume that buries real signals - the precise condition that leads to analyst fatigue and suppression of entire rule channels.

---

## Comparative Results Matrix

| Scenario | MITRE | Phase 1 (Native) | Rule | Level | Phase 2 (Legacy) | EID Generated |
|---|---|---|---|---|---|---|
| Masqueraded PowerShell | T1036+T1059.001 | Captured - behavioral context | 61618 | 12 | Captured - server-side only | ✅ YES |
| LOLBin Non-Standard Parent | T1137+T1059.001 | Captured - behavioral pattern | 92027 | 4 | **Zero telemetry** | ❌ NO |
| Credential Vault DLL | T1555.004 | Captured - tiered path detection | 92158 | 15 | **Zero telemetry** | ❌ NO |

---

## Key Findings

### Finding 1 - Detection intelligence location

The Native config embeds detection intelligence at the sensor level via `groupRelation="and"` - a design choice that the legacy config file does not apply for the tested scenarios. Both schema 4.90 and 4.91 support AND logic; the difference is that `sysmon-native.xml` was built from the ground up with behavioral AND filtering, while `sysmonconfig.xml` relies on OR-based known-vector lists. In Scenario 1, both configs produced alerts - but the Legacy config would fail silently in any environment without a mature server-side ruleset. **The Native config is self-sufficient at the endpoint level.**

### Finding 2 - Known-vector vs behavioral model

Scenarios 2 and 3 produced zero telemetry under the Legacy config. The Legacy model defends against threats that are explicitly catalogued - known parent images, known DLL names. A process executing from a suspicious path with an unlisted parent, or a DLL not in the include list, is completely invisible. **The Native model detects behavioral anomalies - the execution context, not the specific technique.**

### Finding 3 - Security fix: name-only exclusions create bypass surface

Identified during Scenario 3 testing: rule `92153` used `\\\\svchost\.exe$` as a name-only exclusion. A malicious binary named `svchost.exe` in `AppData\Local\Temp` inherited the OS process exclusion and never reached Tier 1 (level 15).

```xml
<!-- BEFORE - name only, bypass possible -->
<field name="win.eventdata.image" type="pcre2" negate="yes">(?i)\\\\svchost\.exe$</field>

<!-- AFTER - full path enforced, bypass blocked -->
<field name="win.eventdata.image" type="pcre2" negate="yes">(?i)[c-z]:\\\\Windows\\\\System32\\\\svchost\.exe$</field>
<field name="win.eventdata.image" type="pcre2" negate="yes">(?i)[c-z]:\\\\Windows\\\\SysWOW64\\\\svchost\.exe$</field>
```

### Finding 4 - Legacy config noise in production

During Phase 2 testing, rule `92041` fired 60+ consecutive times for legitimate `reg.exe` activity from Trend Micro Password Manager. This is the collect-first model in real production conditions. Analysts in this environment learn to suppress high-volume channels - which is exactly where the signal for an actual attack would appear.

---

## Conclusion

The three scenarios produced three distinct behavioral models:

**Scenario 1** - Both configs captured the event, but for different reasons. The Native config filtered at the source with AND logic. The Legacy config sent raw telemetry and the server did the work. The Native model is resilient - it does not depend on server-side intelligence to produce a meaningful alert.

**Scenario 2** - The Legacy config produced zero telemetry. The Native config detected the behavioral anomaly immediately. The attacker's vector (`svchost.exe` from `AppData\Local\Temp`) was not in any Legacy include list. For the Native config, the path risk and parent context were sufficient - no list required.

**Scenario 3** - The Legacy config produced zero telemetry. `vaultcli.dll` is not in the Legacy ImageLoad include list. For the Native config, the risk is determined by where the loading process lives - not by which DLL is being loaded. A new credential dumping technique targeting a different Credential Manager DLL would still be caught by the Native tiered architecture. It would be completely invisible to the Legacy config.

> **The Legacy model answers:** *"Did the attacker use a known technique?"*  
> **The Native model answers:** *"Did the attacker behave anomalously?"*

---

## Greetz

> This project would not have been possible without the pioneering work of SwiftOnSecurity, Olaf Hartong, Carlos Perez, and the entire community that built the Sysmon ecosystem over the years. To the open source community: thank you for your generosity. If errors are found here, they are mine - and I will be grateful for every issue opened and every pull request submitted :)

---
