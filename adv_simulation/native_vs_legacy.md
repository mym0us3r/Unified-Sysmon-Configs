# Native vs Legacy Sysmon - Adversary Simulation Report

**Comparative Detection Validation: Sysmon Native (schema 4.91) vs Sysmon Legacy (schema 4.90)**

![status](https://img.shields.io/badge/status-production--validated-success)
![wazuh](https://img.shields.io/badge/Wazuh-4.14.4-orange)
![sysmon](https://img.shields.io/badge/Sysmon-Native%204.91-red)
![mitre](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-blue)
![platform](https://img.shields.io/badge/platform-Windows%2011%2024H2%2B-lightgrey)

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

> **Rule limitation identified during testing:** rule `92027` has a blind spot for masqueraded parent processes - see [Finding 5](#finding-5---rule-92027-blind-spot-for-masqueraded-parent-processes). The gap was covered by rule `61618` in the same evaluation chain (defense in depth), so detection coverage for Scenario 2 was not lost, but the specific rule limitation is documented below.

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

**Ruleset location:** `/var/ossec/ruleset/rules/` (files `0595` and `0800`-`0950`), `wazuh-analysisd -t` confirmed zero warnings before testing. Agent: `agent.id 009`, `agent.name DELL`, `computer LABDESK`, `agent.ip 192.168.1.3`. Evidence captured directly from Wazuh Discover (`wazuh-alerts-4.x-2026.07.07`).

---

## Attack Scenarios

### Scenario 1 - Masqueraded PowerShell (T1036 + T1059.001)

**Attack:** `powershell.exe` copied to `C:\Users\kr\AppData\Local\Temp\svchost.exe` and executed with `-nop -enc` flags and a Base64-encoded payload.

```cmd
copy "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\Users\kr\AppData\Local\Temp\svchost.exe"

"C:\Users\kr\AppData\Local\Temp\svchost.exe" -nop -enc "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUABvAHcAZQByAFMAaABlAGwAbAAgAE0AYQBzAGsAZQBkACcA"
```

> Decoded payload: `Write-Host 'PowerShell Masked'`

> **Shell note:** invoking the fake binary from `cmd.exe` produces `parentImage=cmd.exe`. Invoking it from an interactive PowerShell session with the call operator (`& "C:\Users\kr\AppData\Local\Temp\svchost.exe" -nop -enc "..."`) produces `parentImage=powershell.exe` instead. Both are valid non-standard-parent conditions for rule `61618`, and both fire identically at level 12 - the detection is anchored on the fake process's own identity and non-standard parent, not on which specific parent invoked it.

---

### Scenario 2 - LOLBin Execution via Non-Standard Parent (T1137 + T1059.001)

**Attack:** `svchost.exe` fake (PowerShell renamed) executing `Start-Process powershell.exe` with obfuscation flags from `AppData\Local\Temp` - simulating LOLBin spawned by a non-standard parent process.

```cmd
cd "C:\Users\kr\AppData\Local\Temp"
svchost.exe -nop -c "Start-Process powershell.exe -ArgumentList '-nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVAAxADEAMwA3AC0AVABlAHMAdAAnAA=='"
```

> **Note:** from a PowerShell prompt this requires the call operator: `& .\svchost.exe -nop -c "..."`.

---

### Scenario 3 - Credential Vault DLL Load from High-Risk Path (T1555.004)

**Attack:** `svchost.exe` fake loading `vaultcli.dll` from `AppData\Local\Temp` via P/Invoke (`LoadLibrary`) - simulating credential dumping via Windows Credential Manager.

```cmd
cd "C:\Users\kr\AppData\Local\Temp"
svchost.exe -nop -c "$a=Add-Type -MemberDefinition '[DllImport(""kernel32.dll"")] public static extern IntPtr LoadLibrary(string s);' -Name L -PassThru; $a::LoadLibrary('C:\Users\kr\AppData\Local\Temp\vaultcli.dll')"
```

> **PowerShell prompt note:** running this literally from an interactive PowerShell session fails, because the outer double quotes cause `$a=...` to be interpolated before reaching the fake binary. Use `-enc` instead, same pattern as Scenarios 1 and 2:
>
> ```powershell
> cd "C:\Users\kr\AppData\Local\Temp"
> $cmd = '$a=Add-Type -MemberDefinition ''[DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string s);'' -Name L -PassThru; $a::LoadLibrary(''C:\Users\kr\AppData\Local\Temp\vaultcli.dll'')'
> $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
> & .\svchost.exe -nop -enc $encoded
> ```
>
> This also requires a `vaultcli.dll` copy to exist at the target path beforehand: `copy "C:\Windows\System32\vaultcli.dll" "C:\Users\kr\AppData\Local\Temp\vaultcli.dll"`.

---

## Phase 1 - Native Sysmon Config Results

> **Config active:** `sysmon-native.xml` (schema 4.91) - `groupRelation="and"` applied at the source - filter-first model

### Scenario 1 - Masqueraded PowerShell

Rule `61618` fired at **level 12** (T1055). The Sysmon Native config captured the process through behavioral context: high-risk execution path, non-standard parent process, and real binary identity exposed via `OriginalFileName=PowerShell.EXE` from the PE header. The process name is `svchost.exe` - legacy logic anchored on `Image=powershell.exe` would have produced zero alerts.

```
rule.id           : 61618
rule.level        : 12
rule.mitre.id      : T1055
rule.mitre.tactic : Defense Evasion, Privilege Escalation
image              : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
originalFileName   : PowerShell.EXE
parentImage        : C:\\Windows\\System32\\cmd.exe
```

![Scenario 1 - Wazuh Discover, rule 61618 firing on the masqueraded svchost.exe](../docs/Scenario%201%20%E2%80%94%20Masqueraded%20PowerShell%20(T1036%20%2B%20T1059.001).png)

*Wazuh Discover - Scenario 1: rule 61618 (level 12, T1055) firing on the masqueraded `svchost.exe`. Five consecutive firings shown, including the original test and the parallel trigger from Scenario 2's own attack chain.*

### Scenario 2 - LOLBin via Non-Standard Parent

The attack chain is captured, but not by the rule one would expect. Rule `92027` (T1059.001, "PowerShell spawned PowerShell") is designed to fire when both `image` and `parentImage` are literally `powershell.exe`. In this scenario the parent is masqueraded - `svchost.exe`, not `powershell.exe` - so `92027`'s `parentImage` condition does not match and the rule does not fire.

Detection instead comes from rule `61618` (T1055), which fires independently at the moment the masqueraded `svchost.exe` process is created, anchored on `OriginalFileName=PowerShell.EXE` from its own PE header rather than on the parent's filename:

```
67027 (EID 4688, Security channel)  - process created (parallel visibility)
  └─► 61618 (T1055, level 12)       - fires on the masqueraded svchost.exe itself
        └─► 92000 (EID 1 anchor, level 3) - the child powershell.exe process
              (92027 evaluated against this event, but its parentImage
               condition does not match Temp\svchost.exe - rule does not fire)
```

```
rule.id    : 61618
rule.level : 12
mitre      : T1055
image      : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
parentImage: (the invoking shell - cmd.exe or powershell.exe, see Scenario 1 shell note)
```

![Scenario 2 - Wazuh Discover, evaluation chain 67027 to 61618 to 92000](../docs/Scenario%202%20%E2%80%94%20LOLBin%20Execution%20via%20Non-Standard%20Parent%20(T1137%20%2B%20T1059.001).png)

*Wazuh Discover - Scenario 2: the full evaluation chain captured in Discover - rule `67027` (EID 4688, parallel visibility), rule `61618` (T1055, level 12, fires on the masqueraded parent), and rule `92000` (EID 1 anchor for the child `powershell.exe` process). No `92027` entry appears in this chain - confirming the blind spot described below.*

This is defense in depth working as intended: `92027` has a blind spot for a masqueraded parent, but `61618` evaluating the same attack chain from a process-identity angle closes it. See [Finding 5](#finding-5---rule-92027-blind-spot-for-masqueraded-parent-processes) for the full rule-level analysis.

### Scenario 3 - Credential Vault DLL Load

Rule `92158` fired at **level 15 - CRITICAL** (T1555.004). The tiered detection architecture worked as designed: the process in `AppData\Local\Temp` was not silenced by Tier 0 and escalated to Tier 1.

```
rule.id    : 92158
rule.level : 15 (CRITICAL)
mitre      : T1555, T1555.004
image      : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
imageLoaded: C:\\Users\\kr\\AppData\\Local\\Temp\\vaultcli.dll
```

![Scenario 3 - Wazuh Discover, rule 92158 CRITICAL alert](../docs/Scenario%203%20%E2%80%94%20Credential%20Vault%20DLL%20Load%20from%20High-Risk%20Path%20(T1555.004).png)

*Wazuh Discover - Scenario 3: rule `92158` (level 15, CRITICAL) - two independent firings, `vaultcli.dll` loaded by the masqueraded `svchost.exe` from `AppData\Local\Temp`.*

Confirmed with 2 independent firings captured in Wazuh Discover, same rule ID, same description, same tiered path logic.

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

![Scenario 1 Legacy - Wazuh Discover, server-side rules 61618/92213/92151 firing](../docs/SYSMON%20LEGACY%20-%20Scenario%201%20%E2%80%94%20Masqueraded%20PowerShell%20(T1036%20%2B%20T1059.001).png)

*Wazuh Discover - Scenario 1, Legacy config: server-side ruleset captured the event via `originalFileName=PowerShell.EXE`, same as documented. Noise from Windows Update activity (`92154`) also visible in the same window - the collect-first model does not filter it at the source.*

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

![Scenario 2 Legacy - Wazuh Discover, zero attack telemetry](../docs/SYSMON%20LEGACY%20-%20Scenario%202%20%E2%80%94%20LOLBin%20Execution%20via%20Non-Standard%20Parent%20(T1137%20%2B%20T1059.001).png)

*Wazuh Discover - Scenario 2, Legacy config: all 6 hits in the attack window are unrelated noise (Windows Update `taskschd.dll` loads, scripting-policy artifacts) - none reference the masqueraded `svchost.exe` or a child `powershell.exe` process. Confirms zero telemetry for the attack itself, not an artifact of a narrow time window.*

### Scenario 3 - Credential Vault DLL Load

**EID 7 was generated, and rule `92153` fired at level 10** - but not for the reason the original version of this report assumed, and not through recognition of `vaultcli.dll` as a credential-theft indicator.

The legacy config's `ImageLoad onmatch="include"` block does **not** contain a DLL-name entry for `vaultcli.dll` - that part of the original finding was correct. What was missed is a separate, generic rule in the same include block, built for DLL Side-Loading detection (T1574.002), that matches on the **loading process's path** rather than the DLL name:

```xml
<ImageLoaded name="technique_id=T1574.002,technique_name=DLL Side-Loading"
             condition="contains any">admin$;c$;\\;\appdata\;\temp\</ImageLoaded>
```

The attack loads `vaultcli.dll` from `C:\Users\kr\AppData\Local\Temp\`, a path that contains both `\appdata\` and `\temp\`. Any DLL loaded from that path would have matched this rule - `vaultcli.dll` was incidental, not recognized. The event that reached Wazuh was then picked up by rule `92153` (server-side ruleset), which does inspect `imageLoaded` for `vaultcli.dll` specifically and produced the description "Suspicious process loaded VaultCli.dll module. Possible use to dump stored passwords."

```
rule.id     : 92153
rule.level  : 10
rule.groups : sysmon, sysmon_eid7_detections, windows
image       : C:\\Users\\kr\\AppData\\Local\\Temp\\svchost.exe
imageLoaded : C:\\Users\\kr\\AppData\\Local\\Temp\\vaultcli.dll
```

![Scenario 3 Legacy - Wazuh Discover, rule 92153 firing by path coincidence](../docs/SYSMON%20LEGACY%20-%20Scenario%203%20%E2%80%94%20Credential%20Vault%20DLL%20Load%20from%20High-Risk%20Path%20(T15555.004).png)

*Wazuh Discover - Scenario 3, Legacy config: rule `92153` (level 10) fires, but the surrounding chain (`92151`, `92213`, `61618`, `92154`) shows this is the same server-side ruleset from Scenarios 1-2, not a purpose-built credential-vault detection. Compare severity directly with the Native config's `92158` at level 15 CRITICAL for the identical attack.*

**Why this matters:** detection here is a side effect of path coincidence, not design. If the attacker had staged `vaultcli.dll` from any path outside the Side-Loading rule's list - `C:\ProgramData\`, for example - Sysmon would not have generated the EID 7 at all, and rule `92153` would have had nothing to evaluate, regardless of how specific its own logic is. Severity is also lower: Legacy classifies this at **level 10**, while the Native config's tiered rule (`92158`) classifies the identical attack at **level 15, CRITICAL** - the same event gets triaged with materially different urgency depending on which config produced it. See [Finding 6](#finding-6---legacy-detection-by-path-coincidence-not-dll-recognition) for the full analysis.

> **Correction note:** the original version of this report stated "Zero EID 7 generated... No rule covers credential vault DLL access by process path context." That statement was based on checking only the DLL-name include list and did not account for the separate path-based Side-Loading rule in the same `ImageLoad` block. The config file itself is unchanged since the original test (single commit, March 23, 2026) - this is a correction to the analysis, not a change in the software under test.

> **Additional observation during Phase 2:** Rule `92041` fired over 60 consecutive times for `reg.exe` spawned by `PwmTower.exe` (Trend Micro Password Manager). This is the collect-first model in production: legitimate software activity generates sustained alert volume that buries real signals - the precise condition that leads to analyst fatigue and suppression of entire rule channels.

---

## Comparative Results Matrix

| Scenario | MITRE | Phase 1 (Native) | Rule | Level | Phase 2 (Legacy) | EID Generated |
|---|---|---|---|---|---|---|
| Masqueraded PowerShell | T1036+T1059.001 | Captured - behavioral context | 61618 | 12 | Captured - server-side only | ✅ YES |
| LOLBin Non-Standard Parent | T1137+T1059.001 | Captured - covered by 61618, not 92027 (see Finding 5) | 61618 * | 12 * | **Zero telemetry** | ❌ NO |
| Credential Vault DLL | T1555.004 | Captured - tiered path detection | 92158 | 15 | Captured - by path coincidence, not DLL recognition (see Finding 6) | ✅ YES ** |

`*` Rule `92027` (L4) has a blind spot against a masqueraded parent and does not fire for this scenario's attack chain; the actual detection comes from `61618` firing on the fake `svchost.exe` process itself. See [Finding 5](#finding-5---rule-92027-blind-spot-for-masqueraded-parent-processes).

`**` Rule `92153` (L10) fires only because the attack path (`AppData\Local\Temp`) matches a generic DLL Side-Loading rule (T1574.002) that triggers on path, not DLL identity. A `vaultcli.dll` staged from a path outside that list would produce zero telemetry under Legacy. Severity is also lower than Native's equivalent (L10 vs L15 CRITICAL). See [Finding 6](#finding-6---legacy-detection-by-path-coincidence-not-dll-recognition).

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

### Finding 5 - Rule 92027 blind spot for masqueraded parent processes

Rule `92027` (T1059.001, "PowerShell spawned PowerShell") anchors detection on a literal path match:

```xml
<field name="win.eventdata.parentImage" type="pcre2">(?i)\\powershell\.exe</field>
```

This assumes the parent process retains its real filename. When the parent is masqueraded - renamed to `svchost.exe`, as in Scenario 2's own attack chain - `parentImage` no longer matches `powershell.exe`, and `92027` does not fire. Sysmon EID 1 has no `ParentOriginalFileName` field, so there is no direct equivalent of `OriginalFileName` for validating the parent's true identity within this rule.

The gap did not translate into a detection failure: rule `61618` (T1055) fires independently at the moment the masqueraded `svchost.exe` process is created, using `OriginalFileName=PowerShell.EXE` from its own PE header rather than depending on the parent's filename. The full evaluation chain observed in production:

```
67027 (EID 4688, Security channel)           - process created (parallel visibility)
  └─► 61618 (T1055, level 12) - fires on the masqueraded svchost.exe itself
        └─► 92000 (EID 1 anchor, level 3) - the child powershell.exe process
              (92027 evaluated against this event, but its parentImage
               condition does not match Temp\svchost.exe - rule does not fire)
```

See the Scenario 2 screenshot above for the raw Discover evidence of this chain.

This is defense in depth working as designed: a path-based rule (`92027`) has a blind spot for a masqueraded parent, but an identity-based rule (`61618`) evaluating the same attack chain from a different angle closes it. It is nonetheless a real limitation worth fixing - a future revision of `92027` should either chain from `if_sid>61618` to add masqueraded-parent coverage, or accept the current asymmetry as intentional and document it as such in the rule's own description field.

### Finding 6 - Legacy detection by path coincidence, not DLL recognition

Scenario 3 under Legacy was originally reported as zero telemetry. Re-testing with the same, unmodified config file (verified via GitHub commit history - single commit, March 23, 2026, no changes since) shows EID 7 **is** generated and rule `92153` **does** fire. The original finding was incomplete, not wrong about what it checked: the DLL-name include list genuinely has no `vaultcli.dll` entry. What it missed is a second, independent rule in the same `ImageLoad` block:

```xml
<ImageLoaded name="technique_id=T1574.002,technique_name=DLL Side-Loading"
             condition="contains any">admin$;c$;\\;\appdata\;\temp\</ImageLoaded>
```

This rule matches on the **path** the DLL was loaded from, not the DLL's identity. It exists to catch DLL side-loading generally (T1574.002), and `AppData\Local\Temp` - the path used in this scenario's attack - happens to satisfy it. Any DLL loaded from that path would trigger the same rule; `vaultcli.dll` receiving a security-relevant description ("Suspicious process loaded VaultCli.dll module") only happens downstream, in Wazuh rule `92153`, which does inspect the DLL name once the raw event exists.

The distinction matters for two reasons:

1. **Coverage is accidental, not guaranteed.** A `vaultcli.dll` loaded from `C:\ProgramData\` or any path outside the Side-Loading rule's list produces zero telemetry under Legacy - the same blind spot the original report described, just narrower than first thought.
2. **Severity is understated.** Legacy classifies the event at **level 10**. The Native config's purpose-built, tiered rule (`92158`) classifies the identical attack at **level 15, CRITICAL**. An analyst triaging by severity alone would treat the same credential-theft attempt very differently depending on which config generated the alert.

This is the inverse of Finding 5: there, a Native rule had a blind spot that a second Native rule covered by design. Here, a Legacy rule "covers" a scenario it was never built to detect, purely because of where the attacker happened to stage the payload - and under-scores it when it does.

---

## Conclusion

The three scenarios produced three distinct behavioral models:

**Scenario 1** - Both configs captured the event, but for different reasons. The Native config filtered at the source with AND logic. The Legacy config sent raw telemetry and the server did the work. The Native model is resilient - it does not depend on server-side intelligence to produce a meaningful alert, and remains resilient across different invoking shells.

**Scenario 2** - The Legacy config produced zero telemetry. The Native config detected the behavioral anomaly - not through the rule originally credited (`92027`, which has a documented blind spot for masqueraded parents), but through `61618` evaluating the same attack chain from the process-identity angle. The attacker's vector (`svchost.exe` from `AppData\Local\Temp`) was not in any Legacy include list and produced no telemetry at all under Legacy; under Native, defense in depth closed the gap that a single rule left open.

**Scenario 3** - The Legacy config captured the event, but not by recognizing `vaultcli.dll` - a generic DLL Side-Loading rule matched because the attack happened to stage the DLL in `AppData\Local\Temp`, a path that rule already watches for unrelated reasons. Stage the same DLL from a path outside that list and Legacy produces zero telemetry, exactly as originally reported for this narrower case. Where it does fire, it also under-classifies the severity (level 10) relative to Native's purpose-built rule (level 15, CRITICAL). For the Native config, the risk is determined by where the loading process lives, deliberately and by design - not by accidentally overlapping with a different rule's path list. A new credential dumping technique targeting a different Credential Manager DLL would still be caught by the Native tiered architecture regardless of staging path. Under Legacy, detection depends on the attacker's path choice colliding with an unrelated rule - which is not something a defender can rely on.

> **The Legacy model answers:** *"Did the attacker use a known technique?"*
> **The Native model answers:** *"Did the attacker behave anomalously?"*

---

## Greetz

> This project would not have been possible without the pioneering work of SwiftOnSecurity, Olaf Hartong, Carlos Perez, and the entire community that built the Sysmon ecosystem over the years. To the open source community: thank you for your generosity. If errors are found here, they are mine - and I will be grateful for every issue opened and every pull request submitted :)

---
