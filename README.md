# 🛡️ Catching the Ghost: Registry Run Key Persistence Detection (MITRE T1547.001)

## 📌 Project Overview
Establishing persistence is a critical phase in the cyber kill chain. Attackers frequently abuse Registry Run Keys to ensure their malicious payloads (backdoors, C2 beacons) survive system reboots. 

This project demonstrates a complete Threat Hunting and Detection Engineering lifecycle: simulating a persistence attack using native binaries (Living off the Land), tuning Sysmon for forensic visibility, and crafting a high-fidelity Wazuh SIEM rule to catch the intrusion instantly.

---

## ⚔️ Phase 1: The Attack (Living off the Land)
To simulate an adversary establishing persistence, I used the native Windows `reg.exe` utility to silently inject a malicious payload (`backdoor.exe`) into the `CurrentVersion\Run` registry key. This technique is designed to bypass basic file-based behavioral monitoring by disguising the payload as a legitimate service (e.g., "WindowsUpdateService").

**The Execution:**
```cmd
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateService" /t REG_SZ /d "C:\Users\Public\backdoor.exe" /f
```
(Image: Attack Execution via CMD)

<img width="976" height="135" alt="persistence_attack_cmd" src="https://github.com/user-attachments/assets/2f0a485f-d302-4e80-b9e5-919a4171486d" />

(Image: The Malicious Key Successfully Implanted in the Registry)

<img width="811" height="360" alt="registry_evidence" src="https://github.com/user-attachments/assets/387602e7-495d-429c-a78b-346550a21a4f" />

---

## 🔍 Phase 2: Detection Engineering & Sysmon Tuning
By default, capturing registry events can create significant noise and CPU overhead. To ensure high visibility without degrading system performance, I applied surgical tuning to the Sysmon configuration XML, specifically targeting the ```CurrentVersion\Run``` paths (Event IDs 12, 13, 14).

The Sysmon XML Tuning:

```XML
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">\Microsoft\Windows\CurrentVersion\Run</TargetObject>
</RegistryEvent>
```
With telemetry flowing, I authored a custom, regex-based PCRE2 rule **(Rule 100067)** in the Wazuh SIEM to detect any unauthorized modifications to these critical keys.

(Image: Custom Detection Rule and Alert in Wazuh)

<img width="801" height="277" alt="persistence_wazuh_alert" src="https://github.com/user-attachments/assets/6b339d25-f6ab-45ad-9ff5-699a92262f7d" />

---

## 🚨 Phase 3: Forensic Analysis & The Result
Upon re-executing the attack, Wazuh instantly triggered a **Level 14 CRITICAL** alert. The telemetry captured the entire forensic footprint of the adversary.

### **Forensic Evidence Extracted:**

* **The Weapon (LotL):**

  image: ```C:\\Windows\\system32\\reg.exe```

* **The Target Key:**

  targetObject: ```HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateService```

* **The Poisoned Payload:**

  details: ```C:\\Users\\Public\\backdoor.exe```

(Image: Highlighted Forensic Evidence from Sysmon Event ID 13)

<img width="792" height="334" alt="persistence_forensic_evidence" src="https://github.com/user-attachments/assets/7462c9fd-f210-4937-afdf-0d6527e0c06f" />

**Author:** Independent Security Researcher | SOC & Detection Engineer

**Framework:** MITRE ATT&CK®
