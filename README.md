# Threat Hunt Report: Persistence via Windows Registry Run Key (Remcos)

<img width="400" src="https://user-images.githubusercontent.com/15206204/278169831-172e4a3c-e3bb-4fd6-b648-c92cbe63aa2f.png" alt="Registry Persistence Threat - Remcos Malware" />

- [Scenario Creation](https://github.com/aduragbemioo/Threat-Event-Persistence-via-Windows-Registry-Run-Key-/blob/main/scenario.md)

---

## Platforms and Tools Used

- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Remcos Remote Access Trojan (RAT)

---

## Scenario

**Reason for Threat Hunt:**  
Unusual system behavior was reported by the Help Desk, including persistent pop-ups and high CPU usage during system startup. Concurrent cybersecurity threat intelligence reports indicated a surge in malware leveraging Windows Registry Run keys—specifically, campaigns involving *Agent Tesla* and *Remcos RAT*.  

The objective was to determine whether any persistence-based malware was present and if it leveraged Registry Run keys for execution upon reboot.

---

## Investigation Steps

### 1. Checked for File Writing via PowerShell

Searched `DeviceProcessEvents` for PowerShell-based file-writing behavior. No results were found.

```kql
DeviceProcessEvents
| where DeviceName  == "ad-stig-impleme"
| where FileName endswith "powershell.exe"
| where ProcessCommandLine has_any ("Copy-Item", "copy", "Out-File", "New-Item", "Set-Content")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
