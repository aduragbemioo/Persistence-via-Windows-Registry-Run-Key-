# Threat Hunt Scenario: Windows Registry Persistence

## 🎯 Threat Event: Persistence via Windows Registry Run Key

**Malicious Persistence Through Registry Modification (Run Key)**

---

## 📌 Reason for Threat Hunt

**Unusual System Behavior Noted by Help Desk**

Several users reported unusual pop-ups and high CPU usage on startup. Additionally, recent cybersecurity reports highlight a wave of malware campaigns (e.g., Agent Tesla, Remcos RAT) using Windows Registry Run keys for persistence.

---

## 🕵️ Steps the "Bad Actor" Took – Logs and IoCs

1. **Gain Access to Endpoint**  
   * Initial compromise via phishing or malicious download.

2. **Drop Payload to Local AppData Folder**  
   * `remcos.exe` dropped at  (Remcos is a remote access trojan (RAT), Note: No real trojan was used in this hunt)
     `C:\Users\<user>\AppData\Roaming\Microsoft\remcos.exe`

3. **Create Registry Entry for Persistence**  
   * Registry key added:  
     `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\remcos`  
   * Value: `"C:\Users\<user>\AppData\Roaming\Microsoft\remcos.exe"`

4. **Payload Executes on Next Reboot or Login**  
   * RAT begins C2 communication (commonly over port 443).

5. **Attacker Maintains Access via Registry-based Persistence**

---

## 📂 Tables Used to Detect IoCs

| Table                  | Purpose                                                                                                                                            |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| **DeviceRegistryEvents** | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) – Detects unauthorized registry modifications |
| **DeviceProcessEvents**  | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) – Identifies execution of suspicious processes |
| **DeviceFileEvents**     | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) – Flags suspicious file creation                 |
| **DeviceNetworkEvents**  | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) – Analyzes outbound RAT communication           |

---

## 🔍 Related Queries

```kusto
// Registry Run Key Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "remcos"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName

// Suspicious File Creation in AppData
DeviceFileEvents
| where FolderPath has "AppData\\Roaming\\Microsoft"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName

// Malicious Payload Execution
DeviceProcessEvents
| where ProcessCommandLine has "remcos.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Outbound Connections from Payload
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "remcos.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine

````

---

## 👤 Created By

* **Author**: Aduragbemi
* **LinkedIn**: [Aduragbemi Oladapo](https://www.linkedin.com/in/aduragbemioladapo/)
* **Date**: June 23, 2025

---

## ✅ Validated By

* **Reviewer**: *TBD*
* **Contact**: *TBD*
* **Date**: *TBD*

---

## 📝 Additional Notes

* Registry Run key persistence is a favored tactic among commodity malware (e.g., Agent Tesla, NanoCore, Remcos).
* Other keys to monitor:

  * `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

---

💻 PowerShell Script: Simulated Persistence via Registry Run Key
powershell
Copy
Edit
# Variables
$dummyExePath = "$env:APPDATA\Microsoft\remcos.exe"
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runKeyName = "remcos"

# Step 1: Copy Dummy Executable
Write-Output "`n[*] Copying dummy executable..."
Copy-Item "C:\Windows\System32\notepad.exe" -Destination $dummyExePath -Force

# Step 2: Add Registry Run Key for Persistence
Write-Output "[*] Adding registry Run key..."
New-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $dummyExePath -PropertyType "String" -Force

# Step 3: Launch Dummy Payload
Write-Output "[*] Launching the dummy payload..."
Start-Process $dummyExePath

# Step 4: Wait for Observation or Simulation
Start-Sleep -Seconds 10

# Step 5: Cleanup Artifacts
Write-Output "[*] Cleaning up..."
Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -Force
Remove-Item $dummyExePath -Force

Write-Output "[+] Done."
📝 Script Summary
This PowerShell script:

Simulates a malicious file drop by copying notepad.exe to a suspicious path.

Adds a Run key to simulate persistence in the Windows Registry.

Executes the dummy payload (notepad.exe).

Waits for 10 seconds.

Cleans up the registry key and file.

⚠️ Note: This script is safe for lab environments and does not download or run malicious code. Always use such simulations in isolated test environments.

## 📅 Revision History

| Version | Changes       | Date          | Modified By                |
| ------- | ------------- | ------------- | -------------------------- |
| 1.0     | Initial Draft | June 23, 2025 | Aduragbemi Oladapo |

---

```
