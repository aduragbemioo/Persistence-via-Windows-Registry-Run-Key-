# Threat Hunt Report: Persistence via Windows Registry Run Key (Remcos)

![image](https://github.com/user-attachments/assets/9d18a0b9-2c4c-4452-aea6-e0f99e176dbb)



- [Scenario Creation](https://github.com/aduragbemioo/Threat-Event-Persistence-via-Windows-Registry-Run-Key-/blob/main/scenario.md)

---

## Platforms and Tools Used

- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Remcos Remote Access Trojan (RAT)

---

## Scenario

**Reason for Threat Hunt:**  
Unusual system behavior was reported by the Help Desk, including persistent pop-ups and high CPU usage during system startup. Concurrent cybersecurity threat intelligence reports indicated a surge in malware leveraging Windows Registry Run keys specifically, campaigns involving *Agent Tesla* and *Remcos RAT*.  

The objective was to determine whether any persistence-based malware was present and, if so, whether it leveraged Registry Run keys for execution upon reboot.

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
```
![image](https://github.com/user-attachments/assets/a22e0aaf-fc3d-486f-8619-3af9875d6aa9)


### 2. Searched `DeviceFileEvents` for Suspicious .exe Drops via PowerShell

Investigated .exe files dropped in non-standard folders often used for malware persistence. Discovered a suspicious file: remcos.exe, created via powershell.
```kql
DeviceFileEvents
| where DeviceName  == "ad-stig-impleme"
| where FileName endswith ".exe"
| where FolderPath has_any (
    "AppData", 
    "Temp", 
    "Downloads", 
    "Desktop", 
    "Roaming", 
    "Local", 
    "Microsoft"
)
| where InitiatingProcessFileName contains "powershell"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
I found remcos.exe
![image](https://github.com/user-attachments/assets/027b4d51-c919-43ae-8962-39dd51f715b1)

### 3. Detected Registry Persistence via Run Key
Confirmed that remcos.exe was registered in the Windows Run key for automatic startup. The registry modification was made by powershell_ise.exe.
```kql
DeviceRegistryEvents
| where DeviceName  == "ad-stig-impleme"
| where RegistryKey endswith @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "remcos"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```
![image](https://github.com/user-attachments/assets/37c8b5c5-88af-4bff-a017-14ac57b1f9c4)

### 4. Checked `DeviceProcessEvents` for Execution of remcos.exe
Validated that remcos.exe was executed post-persistence setup.

```kql
DeviceProcessEvents
| where DeviceName  == "ad-stig-impleme"
| where ProcessCommandLine has "remcos.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```

![image](https://github.com/user-attachments/assets/0c0c6dae-dd86-4fb5-a62a-85fe1d2a43f7)

### 5. Checked `DeviceNetworkEvents` for Network Activity from remcos.exe
Looked for outbound network connections from the malicious binary but found none.
```kql
DeviceNetworkEvents
| where DeviceName  == "ad-stig-impleme"
| where InitiatingProcessFileName =~  "remcos.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine

```
![image](https://github.com/user-attachments/assets/6352932a-afc2-4ca9-81e3-f815167904ea)


## Chronological Event Timeline

### 1. Suspicious File Drop

- **Timestamp:** 2025-06-23T22:28:20.4568851Z 
- **Event:** Dropped `remcos.exe` into a non-standard directory via PowerShell.  
- **Path:** C:\Users\vullab\AppData\Roaming\Microsoft\remcos.exe

---

### 2. Registry Key Persistence Established

- **Timestamp:** 2025-06-23T22:28:09.9474037Z  
- **Event:** Remcos added to Windows Run key via `powershell_ise.exe`.  
- **Registry Path:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- **Value Name:** `remcos`  

---

### 3. Execution of remcos.exe

- **Timestamp:** 2025-06-23T22:28:10.4019698Z  
- **Event:** Execution of the dropped malicious binary confirmed.  
- **Command Line:** Included `remcos.exe`, potentially indicating payload launch.  

---

### 4. No Network Communication Observed

- **Event:** No external connections were made by `remcos.exe`, indicating either incomplete setup or use of alternate communication mechanisms.  

---

## Summary

The device `ad-stig-impleme` exhibited signs of compromise via Windows Registry persistence. A suspicious executable (`remcos.exe`) was dropped using PowerShell and added to the Run registry key for startup persistence. The file was later executed, confirming a successful persistence attack. No external communication was observed at this stage.

---

## Response Taken

- Device `ad-stig-impleme` was **isolated from the network**.  
- A full malware scan and forensic dump were initiated.  
- SOC team notified for deeper analysis and possible threat actor attribution.
