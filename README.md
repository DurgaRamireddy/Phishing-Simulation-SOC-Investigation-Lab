# Phishing Simulation & SOC Investigation Lab

> **MITRE ATT&CK Coverage:** T1566.002 · T1204.001 · T1078 · T1056.003  
> **Tools:** GoPhish · Splunk Enterprise · Splunk Universal Forwarder · VMware  
> **Analyst:** Durga Sai Sri Ramireddy | MS Cybersecurity, University of Houston

---

## Overview

End-to-end phishing simulation and SOC investigation lab built in a VMware isolated environment. This project simulates a real-world credential harvesting phishing campaign — from attacker infrastructure setup through victim execution, credential capture, and full SIEM-based investigation.

The lab was designed to produce actionable, portfolio-quality forensic evidence using only Windows Security event logs, demonstrating that process creation logging alone can surface phishing execution without network-level visibility.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│              Host-Only Network: 192.168.255.0/24     │
│                                                      │
│  ┌──────────────────┐      ┌──────────────────────┐  │
│  │  Ubuntu VM        │      │  Windows 10 VM        │  │
│  │  192.168.255.131  │◄─────│  192.168.255.132      │  │
│  │                  │      │                      │  │
│  │  • Splunk 9.3.2  │      │  • Victim Endpoint   │  │
│  │  • GoPhish 0.12.1│      │  • SUF 10.2.1        │  │
│  │  (Attacker Infra)│      │  • Log Source        │  │
│  └──────────────────┘      └──────────────────────┘  │
│                                                      │
│  ┌──────────────────┐                               │
│  │  Kali Linux VM   │                               │
│  │  192.168.255.130 │                               │
│  │  • Attack Sim    │                               │
│  └──────────────────┘                               │
└─────────────────────────────────────────────────────┘
```

**Log Pipeline:** Windows 10 → Splunk Universal Forwarder (port 9997) → Splunk Enterprise on Ubuntu

---

## Attack Chain

```
[1] SETUP          [2] DELIVERY       [3] EXECUTION      [4] CAPTURE
GoPhish deployed → Phishing email  → Victim clicks  → Credentials
on Ubuntu         crafted with       link at            harvested:
with fake IT      spoofed sender     22:50:44           john.doe /
portal page       and urgent CTA     Edge from          Password123
                                     explorer.exe
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Evidence |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | GoPhish campaign with spoofed IT identity |
| User Execution: Malicious Link | T1204.001 | Execution | Edge spawned by explorer.exe at 22:50:44 (EventID 4688) |
| Valid Accounts | T1078 | Defense Evasion | Harvested credentials captured by GoPhish |
| Web Portal Capture | T1056.003 | Credential Access | Fake login form submitted to attacker server |

---

## Key Forensic Finding

The critical indicator of compromise was **Microsoft Edge launched directly from `explorer.exe`** — captured via Windows Security EventID 4688:

```
Time:    2026-03-16 22:50:44
Process: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
Parent:  C:\Windows\explorer.exe
Host:    DESKTOP-FL9KRGR
```

This process parent-child relationship is a reliable signal for user-initiated phishing link execution — distinct from normal browser launches triggered by other processes.

---

## Splunk Detection Queries

### T1566 — Browser Activity Timeline
```spl
index=main host="DESKTOP-FL9KRGR" EventCode=4688 New_Process_Name="*msedge*"
| table _time, New_Process_Name, Creator_Process_Name
| sort _time
```

### T1204 — User Execution from Explorer (Key IOC)
```spl
index=main host="DESKTOP-FL9KRGR" EventCode=4688 Creator_Process_Name="*explorer*"
| table _time, New_Process_Name, Creator_Process_Name
| sort _time
```

### T1078 — Account Logon Events
```spl
index=main host="DESKTOP-FL9KRGR" EventCode=4624
| table _time, Account_Name, Logon_Type, Source_Network_Address
| sort _time
```

### Credential Access Activity Over Time
```spl
index=main host="DESKTOP-FL9KRGR" EventCode=5379
| timechart count span=15m
```

---

## Splunk Dashboard

4-panel SOC investigation dashboard built from the queries above:

| Panel | Query | Purpose |
|---|---|---|
| T1566 - Browser Activity Timeline | EventCode=4688 + msedge filter | Phishing window visualization |
| T1204 - User Execution from Explorer | EventCode=4688 + explorer parent | Smoking gun: phishing click |
| T1078 - Account Logon Events | EventCode=4624 | Account activity during attack |
| Credential Access Over Time | EventCode=5379 timechart | Credential manager spike detection |

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP | 192.168.255.131 | GoPhish phishing server |
| URL | `http://192.168.255.131/?rid=SrjXtqB` | Phishing landing page with campaign ID |
| Email | it-support@company-internal.com | Spoofed sender identity |
| Credentials | john.doe@company-internal.com / Password123 | Harvested credentials |
| Process | msedge.exe spawned by explorer.exe | Phishing click indicator |

---

## Detection Gaps & Lessons Learned

**Gaps identified:**
- No network-level URL visibility — Sysmon EventID 3 or a network tap would capture the actual URL visited. Process creation logging confirmed execution but not destination.
- EventID 5379 field values (`Target_Name`, `User_Name`) were empty with default audit policy — advanced audit policy required for full credential access logging.

**What worked well:**
- Splunk Universal Forwarder via port 9997 was stable and reliable (HEC abandoned due to persistent `code 17 — globally disabled` errors in this VMware environment)
- EventID 4688 process creation logging provided sufficient evidence to confirm phishing execution without network visibility
- GoPhish dashboard provided immediate confirmation of credential capture

---

## Recommended Detections (Production)

```spl
// Alert: Browser spawned by explorer.exe outside business hours
index=main EventCode=4688
  (New_Process_Name="*chrome*" OR New_Process_Name="*msedge*" OR New_Process_Name="*firefox*")
  Creator_Process_Name="*explorer*"
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| stats count by host, New_Process_Name, _time

// Alert: Credential manager access spike
index=main EventCode=5379
| bucket _time span=5m
| stats count by _time, host
| where count > 50
```

---

## Recommended Defensive Controls

1. **MFA on all accounts** — harvested passwords become useless
2. **Email security gateway** with URL rewriting and sandboxing (Proofpoint, Mimecast)
3. **DNS filtering** (Cisco Umbrella) to block phishing domains at resolution
4. **Sysmon deployment** with SwiftOnSecurity config for network connection logging (EventID 3)
5. **Regular phishing simulation training** for all users

---

## Project Structure

```
├── README.md                          # This file
├── Phishing_SOC_Incident_Report.docx  # Full incident report
└── splunk/
    └── dashboard_phishing_soc.xml     # Splunk dashboard export (add after export)
```

---

## Related Projects

- [Splunk HOME SOC Detection Lab](https://github.com/DurgaRamireddy/Splunk-HOME-SOC-Detection-Lab---End-to-End-Alert-Lifecycle) — Full SOC T1 alert lifecycle with Hydra brute force, PowerShell persistence detection, EventID-based detections, 4-panel dashboard

---

*All activity conducted in an isolated VMware lab environment. No real systems or credentials were involved.*
