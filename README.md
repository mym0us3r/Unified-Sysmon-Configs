# 🛡️ Unified Sysmon Configs

**Consolidated Sysmon configurations (Native & Legacy) optimized for Wazuh, SIEM/XDR, and Threat Hunting.**

---

## 💡 Why this repository?
Sysmon has evolved. With Windows 11 (v24H2+), it is now a native feature, but managing configurations and keeping Wazuh rules updated requires constant attention. 

I created this hub to centralize what works in the field. This project provides production-ready XMLs and rulesets to help you maintain visibility, whether you are using the new Native Sysmon or the classic Sysinternals binary.

## 🚀 Repository Structure

### ⚙️ The Configurations
* **/configs/native**: XMLs specifically tuned for the new Windows 11 Native Sysmon.
* **/configs/legacy**: Reliable baselines for traditional `sysmon.exe` deployments.

### 🛡️ Wazuh Ruleset (The Logic)
I have included two sets of rules for comparison and auditing:
* **/ruleset/wazuh-server-4.14**: Rules pulled from a running Wazuh 4.14.0 server.
* **/ruleset/wazuh-official-repo**: The latest master-branch rules from Wazuh's official GitHub.

### 📚 Documentation
* **/docs**: Quick guides and visual tips, including how to verify the Sysmon driver in its native state.

## 🛠️ Quick Start
1. Select a configuration from `/configs`.
2. Apply it: `sysmon -c your_config.xml` (or use the native dashboard).
3. Ensure your Wazuh rules in `/var/ossec/etc/rules/` align with the ones in this repo to avoid blind spots.

---
*Maintained by **K1sh** – Senior Cybersecurity Analyst and Wazuh Ambassador. Contributions and issues are welcome.*
